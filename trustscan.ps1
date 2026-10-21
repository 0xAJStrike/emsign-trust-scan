#requires -Version 7
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

<#
.SYNOPSIS
  Windows-native scan for eMudhra/emSign compromised certificates (Oct 2026).

.DESCRIPTION
  PowerShell counterpart to trustscan.py. It inventories the Windows certificate
  stores in BOTH scopes (CurrentUser + LocalMachine) across the logical stores
  that matter for this incident -- Root, CA, My, TrustedPublisher, AuthRoot --
  plus Group-Policy-pushed roots in the registry, and optionally env-var CA
  bundles and files/directories you pass.

  Each certificate is matched the same four ways as the Python tool:
    compromised_ca_cert       (exact cert SHA-256)
    compromised_key_reuse     (SubjectPublicKeyInfo SHA-256 -- cross-signs/re-issues)
    issued_by_compromised_ca  (AuthorityKeyIdentifier -> compromised CA)
    distrust_root_present     (an emSign root to distrust)
  The legitimate Sectigo root "AAA Certificate Services" is not flagged by default:
  it cross-signed the bad intermediates, so it anchors their second trust path,
  but most OS and library stores still trust it and dropping it breaks legitimate
  sites. -FlagAaa reports it as an INFO finding (cross_sign_root_present) for
  teams that have chosen to remove it. Every run ends with a one-line caveat
  about that path.

  IOC data comes from emsign_iocs.json (built/verified by tools/build_iocs.py).
  Exit codes: 0 = clean (INFO-only results count as clean), 1 = findings,
  2 = IOC load error.

.EXAMPLE
  pwsh -File trustscan.ps1
.EXAMPLE
  pwsh -File trustscan.ps1 -Path C:\certs\ -Format csv > findings.csv
#>

[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$IocFile,
    [ValidateSet('store', 'env', 'paths', 'all')][string[]]$Source = @('all'),
    [ValidateSet('text', 'json', 'csv')][string]$Format = 'text',
    [switch]$FlagAaa
)

# --------------------------------------------------------------------------- #
# IOC data
# --------------------------------------------------------------------------- #
if (-not $IocFile) { $IocFile = Join-Path $PSScriptRoot 'emsign_iocs.json' }
try {
    $ioc = Get-Content -LiteralPath $IocFile -Raw -ErrorAction Stop | ConvertFrom-Json
}
catch {
    [Console]::Error.WriteLine("error: could not load IOC file ${IocFile}: $_")
    exit 2
}

$CompCert = @{}; $CompSpki = @{}; $DistrustCert = @{}; $DistrustSpki = @{}
$ContextCert = @{}; $ContextSpki = @{}
$Ski = [System.Collections.Generic.HashSet[string]]::new()
foreach ($c in $ioc.compromised_certs) {
    $CompCert[$c.cert_sha256.ToLower()] = $c
    if (-not $CompSpki.ContainsKey($c.spki_sha256.ToLower())) { $CompSpki[$c.spki_sha256.ToLower()] = $c }
}
foreach ($s in $ioc.compromised_subject_key_identifiers) { [void]$Ski.Add($s.ToLower()) }
foreach ($r in $ioc.affected_roots) {
    if ($r.action -eq 'review_distrust') {
        $DistrustCert[$r.cert_sha256.ToLower()] = $r
        $DistrustSpki[$r.spki_sha256.ToLower()] = $r
    }
    elseif ($r.action -eq 'legitimate_root_context') {
        $ContextCert[$r.cert_sha256.ToLower()] = $r
        $ContextSpki[$r.spki_sha256.ToLower()] = $r
    }
}

# Printed once per run (not per finding): a trust-store scan cannot prove a client
# rejects forged chains, because the compromised intermediates are also cross-signed
# by the legitimate AAA Certificate Services root. That root CAN be removed (Firefox
# and Chrome already distrust it for TLS; Homebrew's bundle drops it) but most OS and
# library stores still trust it and dropping it breaks many legitimate sites, so it
# is not flagged by default.
$AaaCaveat = 'Note: this scan does not prove the host rejects forged chains. The compromised intermediates are also cross-signed by AAA Certificate Services, a legitimate root that most OS and library stores still trust and that this tool does not flag by default (removing it breaks many legitimate sites; -FlagAaa reports it). A client that skips revocation can still accept a forged chain through it even with every emSign root gone. Full remediation needs the eight intermediate keys blocked by SPKI (as Chrome and Go do), the client patched, or revocation checking enabled.'

# --------------------------------------------------------------------------- #
# cert helpers
# --------------------------------------------------------------------------- #
function Get-Sha256Hex([byte[]]$Bytes) {
    [System.Convert]::ToHexString([SHA256]::HashData($Bytes)).ToLower()
}

function Get-SpkiSha256($Cert) {
    try { return Get-Sha256Hex $Cert.PublicKey.ExportSubjectPublicKeyInfo() } catch { return $null }
}

function Get-AkiHex($Cert) {
    $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.35' } | Select-Object -First 1
    if (-not $ext) { return $null }
    # AuthorityKeyIdentifier value is SEQUENCE { [0] keyIdentifier ... }; the
    # keyIdentifier is the context-tag 0x80 primitive. Byte-scan for it.
    $raw = $ext.RawData
    for ($i = 0; $i -lt $raw.Length - 1; $i++) {
        if ($raw[$i] -eq 0x80) {
            $len = $raw[$i + 1]
            if ($len -gt 0 -and ($i + 2 + $len) -le $raw.Length) {
                return [System.Convert]::ToHexString($raw[($i + 2)..($i + 1 + $len)]).ToLower()
            }
        }
    }
    return $null
}

function Test-Cert($Cert, [string]$Source, [string]$Location) {
    $findings = @()
    $certFp = Get-Sha256Hex $Cert.RawData
    $spkiFp = Get-SpkiSha256 $Cert
    $serial = $Cert.SerialNumber.ToLower()
    if ($serial.Length % 2) { $serial = '0' + $serial }
    $subject = $Cert.Subject

    function New-F($sev, $type, $name, $scalar, $detail) {
        [pscustomobject]@{
            severity = $sev; type = $type; source = $Source; location = $Location
            subject = $subject; serial = $serial; cert_sha256 = $certFp
            spki_sha256 = ($spkiFp ?? ''); matched_name = $name
            recovered_scalar = $scalar; detail = $detail
        }
    }

    if ($CompCert.ContainsKey($certFp)) {
        $e = $CompCert[$certFp]
        $findings += New-F 'CRITICAL' 'compromised_ca_cert' $e.name $e.recovered_scalar `
            "exact compromised intermediate (issued by $($e.issued_by))"
    }
    elseif ($spkiFp -and $CompSpki.ContainsKey($spkiFp)) {
        $e = $CompSpki[$spkiFp]
        $findings += New-F 'CRITICAL' 'compromised_key_reuse' $e.name $e.recovered_scalar `
            'different certificate carrying a compromised private key'
    }

    if ($DistrustCert.ContainsKey($certFp)) {
        $e = $DistrustCert[$certFp]
        $findings += New-F 'CRITICAL' 'distrust_root_present' $e.name $null `
            'distrusted emSign root still trusted here; forged chains from the leaked intermediate keys validate against it. Remove it or update the bundle. This alone does not close the AAA cross-sign path: block the intermediate keys or enable revocation checking.'
    }
    elseif ($spkiFp -and $DistrustSpki.ContainsKey($spkiFp)) {
        $e = $DistrustSpki[$spkiFp]
        $findings += New-F 'CRITICAL' 'distrust_root_present' $e.name $null `
            'distrusted emSign root key present under a different cert; forged chains from the leaked intermediate keys validate against it. Remove it. This alone does not close the AAA cross-sign path: block the intermediate keys or enable revocation checking.'
    }

    if ($FlagAaa) {
        $ctx = $null
        if ($ContextCert.ContainsKey($certFp)) { $ctx = $ContextCert[$certFp] }
        elseif ($spkiFp -and $ContextSpki.ContainsKey($spkiFp)) { $ctx = $ContextSpki[$spkiFp] }
        if ($ctx) {
            $findings += New-F 'INFO' 'cross_sign_root_present' $ctx.name $null `
                'legitimate cross-signing root present; it anchors the compromised intermediates'' second trust path. Not flagged by default because most stores still trust it and dropping it breaks legitimate sites; reported for teams that have chosen to remove it (as Homebrew''s bundle does).'
        }
    }

    if (-not $CompCert.ContainsKey($certFp) -and -not ($spkiFp -and $CompSpki.ContainsKey($spkiFp))) {
        $aki = Get-AkiHex $Cert
        if ($aki -and $Ski.Contains($aki)) {
            $findings += New-F 'HIGH' 'issued_by_compromised_ca' $aki $null `
                'certificate was issued by a compromised intermediate; treat as forgeable / replace'
        }
    }
    return $findings
}

function Get-CertsFromFile([string]$FilePath) {
    $certs = @()
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    try {
        if ($ext -in '.p7b', '.p7c') {
            $col = [X509Certificate2Collection]::new(); $col.Import($FilePath); $certs += $col
        }
        elseif ($ext -in '.pfx', '.p12') {
            foreach ($pw in 'changeit', '') {
                try {
                    $col = [X509Certificate2Collection]::new()
                    $col.Import($FilePath, $pw, [X509KeyStorageFlags]::DefaultKeySet)
                    $certs += $col; break
                }
                catch {}
            }
        }
        else {
            $text = Get-Content -Raw -LiteralPath $FilePath -ErrorAction Stop
            if ($text -match '-----BEGIN CERTIFICATE-----') {
                foreach ($m in [regex]::Matches($text, '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----')) {
                    try { $certs += [X509Certificate2]::new([System.Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))) } catch {}
                }
            }
            else {
                try { $certs += [X509Certificate2]::new($FilePath) } catch {}
            }
        }
    }
    catch {}
    return $certs
}

# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #
function Scan-Stores {
    $out = @()
    foreach ($scope in 'CurrentUser', 'LocalMachine') {
        foreach ($name in 'Root', 'CA', 'My', 'TrustedPublisher', 'AuthRoot') {
            $p = "Cert:\$scope\$name"
            if (-not (Test-Path $p)) { continue }
            try { $items = Get-ChildItem -Path $p -ErrorAction Stop } catch { continue }
            foreach ($c in $items) { if ($c -is [X509Certificate2]) { $out += Test-Cert $c 'windows-store' $p } }
        }
    }
    return $out
}

function Get-DerFromCertBlob([byte[]]$Blob) {
    # Serialized cert property store: repeated (propId:u32, reserved:u32,
    # len:u32, data[len]). The DER cert is property id 0x20 (CERT_CERT_PROP_ID).
    $i = 0
    while ($i + 12 -le $Blob.Length) {
        $propId = [System.BitConverter]::ToUInt32($Blob, $i)
        $len = [System.BitConverter]::ToUInt32($Blob, $i + 8)
        $start = $i + 12
        if ($start + $len -gt $Blob.Length) { break }
        if ($propId -eq 32) { return $Blob[$start..($start + $len - 1)] }
        $i = $start + $len
    }
    return $null
}

function Scan-GpoRegistry {
    $out = @()
    $keys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'
        'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates'
        'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        foreach ($sub in Get-ChildItem $k -ErrorAction SilentlyContinue) {
            try {
                $blob = (Get-ItemProperty -Path $sub.PSPath -Name Blob -ErrorAction Stop).Blob
                $der = Get-DerFromCertBlob $blob
                if ($der) { $out += Test-Cert ([X509Certificate2]::new([byte[]]$der)) 'windows-gpo' $sub.PSChildName }
            }
            catch {}
        }
    }
    return $out
}

function Scan-Env {
    $out = @()
    foreach ($v in 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS') {
        $val = [System.Environment]::GetEnvironmentVariable($v)
        if ($val -and (Test-Path -LiteralPath $val -PathType Leaf)) {
            foreach ($c in Get-CertsFromFile $val) { $out += Test-Cert $c "env:$v" $val }
        }
    }
    return $out
}

function Scan-Paths([string[]]$Paths) {
    $out = @()
    $exts = '.pem', '.crt', '.cer', '.der', '.cert', '.p7b', '.p7c', '.p12', '.pfx'
    foreach ($p in $Paths) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            foreach ($f in Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue) {
                if ($f.Extension.ToLower() -in $exts) {
                    foreach ($c in Get-CertsFromFile $f.FullName) { $out += Test-Cert $c 'file' $f.FullName }
                }
            }
        }
        elseif (Test-Path -LiteralPath $p -PathType Leaf) {
            foreach ($c in Get-CertsFromFile $p) { $out += Test-Cert $c 'file' $p }
        }
    }
    return $out
}

# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
$src = if ($Source -contains 'all') { @('store', 'env', 'paths') } else { $Source }
$all = @()
if ($src -contains 'store') { $all += Scan-Stores; $all += Scan-GpoRegistry }
if ($src -contains 'env') { $all += Scan-Env }
if (($src -contains 'paths') -and $Path) { $all += Scan-Paths $Path }

# dedupe + sort by severity
$seen = @{}; $dedup = @()
foreach ($f in $all) {
    $key = '{0}|{1}|{2}|{3}' -f $f.type, $f.source, $f.location, $f.cert_sha256
    if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $dedup += $f }
}
$rank = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }
$dedup = @($dedup | Sort-Object @{ e = { $rank[$_.severity] } }, type, location)

switch ($Format) {
    'json' {
        if ($dedup.Count) { $dedup | ConvertTo-Json -Depth 4 -AsArray } else { '[]' }
        [Console]::Error.WriteLine($AaaCaveat)
    }
    'csv' {
        $dedup | ConvertTo-Csv -NoTypeInformation
        [Console]::Error.WriteLine($AaaCaveat)
    }
    default {
        $stamp = if ($ioc.generated) { " (IOC data generated $($ioc.generated))" } else { '' }
        if (-not $dedup.Count) {
            "No eMudhra/emSign compromised certificates found in the scanned stores.$stamp"
        }
        else {
            foreach ($f in $dedup) {
                "[$($f.severity)] $($f.type)  ($($f.source))"
                "    location : $($f.location)"
                "    subject  : $($f.subject)"
                "    serial   : $($f.serial)"
                "    cert     : $($f.cert_sha256)"
                "    spki     : $($f.spki_sha256)"
                if ($f.matched_name) {
                    $line = "    matched  : $($f.matched_name)"
                    if ($null -ne $f.recovered_scalar) { $line += "  (private key = $($f.recovered_scalar))" }
                    $line
                }
                "    note     : $($f.detail)"
                ''
            }
            $counts = $dedup | Group-Object severity | ForEach-Object { "$($_.Count) $($_.Name)" }
            "Summary: $($dedup.Count) finding(s): $($counts -join ', ')$stamp"
        }
        ''
        $AaaCaveat
    }
}

# INFO-only findings (e.g. -FlagAaa surfacing AAA) are not failures.
$failing = @($dedup | Where-Object { $_.severity -ne 'INFO' })
exit ([int]($failing.Count -gt 0))
