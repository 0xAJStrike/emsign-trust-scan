# emSign / eMudhra compromise - trust-store scanner

Detection tooling for the **October 2026 eMudhra / emSign intermediate CA
private-key compromise**. Eight intermediate CAs were issued with P-384 keys
whose private scalars were tiny integers (recovered values `4, 56, 66, 115, 155,
156, 230, 237`), so anyone can trivially forge certificates that chain to them.
Browsers and OS trust stores pushed distrust quickly - but **most non-browser
trust stores don't update automatically**, which is what this tool finds.

> Status: the incident is live. The bundled IOC data carries a `generated` date;
> re-run the generator (below) to refresh it.

**`trustscan`** (Python) and **`trustscan.ps1`** (Windows/PowerShell) inventory
the trust stores and CA bundles on a host and flag anything matching the affected
certs. Pure-stdlib + `cryptography`; no other dependencies.

## Quickstart

```bash
# scan this host's trust stores and CA bundles
python trustscan.py

# machine-readable for ticketing
python trustscan.py --format csv > findings.csv
```

```powershell
# Windows-native: cert stores (both scopes) + GPO roots + env bundles
pwsh -File trustscan.ps1
```

Exit codes: `0` = clean, `1` = finding(s), `2` = error.

## How a cert is matched

Every certificate found at any location below is fingerprinted and checked four ways:

| Match | Severity | Meaning |
|---|---|---|
| `compromised_ca_cert` | CRITICAL | exact compromised intermediate (cert SHA-256) |
| `compromised_key_reuse` | CRITICAL | a *different* cert carrying a compromised **key** (SPKI SHA-256) - catches the Sectigo cross-signs and any re-issue |
| `issued_by_compromised_ca` | HIGH | a leaf/sub-CA whose AuthorityKeyIdentifier points at a compromised intermediate - forgeable |
| `distrust_root_present` | CRITICAL | a distrusted emSign root is still trusted here. Its own key is intact - but the intermediate keys are public, so while this root is trusted a forged cert for **any** domain validates for every client that doesn't check revocation (most non-browser clients). Remove it / update the bundle |

The legitimate Sectigo root **AAA Certificate Services is never flagged** - it
only cross-signed the bad intermediates and remains valid.

## Where `trustscan` looks

### File bundles

| Source | What it is | Locations checked |
|---|---|---|
| `certifi` | Python CA bundle | `certifi.where()` (resolved at runtime) |
| `bundles` → distro | OS `ca-certificates` aggregate | `/etc/ssl/certs/ca-certificates.crt` · `/etc/pki/tls/certs/ca-bundle.crt` · `/etc/ssl/cert.pem` |
| `bundles` → FreeBSD | `ca_root_nss` | `/usr/local/share/certs/ca-root-nss.crt` · `/usr/local/etc/ssl/cert.pem` |
| `bundles` → Homebrew | brew `ca-certificates` | `/opt/homebrew/etc/ca-certificates/cert.pem` · `/usr/local/etc/ca-certificates/cert.pem` · `/usr/local/etc/openssl*/cert.pem` |
| `bundles` → curl | standalone curl bundle | `/usr/local/share/curl/curl-ca-bundle.crt` · `C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt` · `C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt` |
| `bundles` → pip | pip's vendored certifi | `<pip>/_vendor/certifi/cacert.pem` (resolved via `import pip`) |
| `nss` | Firefox / Thunderbird / Chrome-Linux NSS DB | `~/.mozilla/firefox/*/cert9.db` · `~/.thunderbird/*/cert9.db` · `~/snap/firefox/common/.mozilla/firefox/*/cert9.db` · `~/.pki/nssdb/cert9.db` · `%APPDATA%\Mozilla\Firefox\Profiles\*\cert9.db` · `%APPDATA%\Thunderbird\Profiles\*\cert9.db` |

### OS trust stores & other sources

| Source | Locations checked |
|---|---|
| `os` (Linux) | `/etc/ssl/certs` · `/usr/local/share/ca-certificates` · `/etc/pki/tls/certs` · `/etc/pki/ca-trust/extracted/pem` (recursed) |
| `os` (macOS) | `security find-certificate -a -p` on default keychains + `SystemRootCertificates.keychain` |
| `os` (Windows, Python) | `ssl.enum_certificates` for `ROOT`, `CA`, `MY`, `TrustedPublisher`, `AuthRoot` + Group-Policy-pushed LocalMachine roots (registry) |
| `java` | `$JAVA_HOME` + JVM roots (`/usr/lib/jvm/*`, `/opt/java/*`, `/Library/Java/JavaVirtualMachines/*`, `C:\Program Files\Java\*`, Adoptium, Corretto, Microsoft) → `.../lib/security/cacerts` |
| `env` | files in `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`; directory in `SSL_CERT_DIR` |
| `paths` | any files/directories you pass |
| `--rootfs <dir>` | the distro/curl/Java store locations **inside** an extracted container image |

> `env` variables hold a **path**, not cert data - `trustscan` reads the file(s)
> at that path.

### Python virtualenvs, conda & other vendored bundles - use `--path`

certifi is **not** the only Python package that ships its own CA roots. These
bundle their own `*.pem` inside `site-packages`, independent of both certifi and
the OS store:

| Package | Bundled file |
|---|---|
| botocore (AWS CLI / boto3) | `botocore/cacert.pem` |
| grpcio (gRPC) | `grpc/_cython/_credentials/roots.pem` |
| httplib2 | `httplib2/cacerts.txt` (odd extension - pass the file directly) |
| requests (legacy <2.16) | `requests/cacert.pem` |

The default scan auto-locates **only** certifi and pip's vendored certifi, and
**only for the interpreter running `trustscan.py`**. Everything else above - plus
every other virtualenv or conda env on the box - must be scanned explicitly by
pointing `--path` at `site-packages`:

```bash
python trustscan.py "$(python -c 'import site;print(site.getsitepackages()[0])')"
# or cover many environments at once
python trustscan.py /opt/venvs/ /home/*/.virtualenvs/ /opt/conda/envs/
```

```powershell
# Windows / PowerShell equivalent
python trustscan.py (python -c "import site; print(site.getsitepackages()[0])")
```

The OS root store (`/etc/ssl/certs`, etc.) does **not** include these - libraries
bundle their own copy precisely so they don't depend on it. A directory scan only
opens cert-extension files, so an odd name like `cacerts.txt` must be passed as a
file directly.

### Windows (`trustscan.ps1`) goes further

The Python `os` source covers LocalMachine stores and LocalMachine GPO roots.
`trustscan.ps1` adds the one thing the Python stdlib can't reach without Win32
interop: the **`CurrentUser` scope** (same logical stores) - plus it handles
`env` bundles and `-Path` files/dirs natively. Use it when per-user trust matters;
otherwise the Python tool's Windows coverage is equivalent.

### Certificate formats

PEM/DER X.509, PKCS#7 (`.p7b/.p7c`), PKCS#12 (`.p12/.pfx`, tried with
`changeit`/empty), and JKS keystores - all parsed with the stdlib only.

## Scope & limitations (read this)

**A clean result does not mean the host is safe.** The compromised intermediates
were also cross-signed by Sectigo's `AAA Certificate Services`, a legitimate,
widely-trusted root that cannot be removed and that this tool never flags by
default. A client that does not check revocation can still accept a forged chain
through that path even with every emSign root gone. The real fix is to block the
eight intermediates, patch the client, or enable revocation, not just remove a
root. This scanner finds stale and known-bad trust anchors; it does not prove a
client rejects forged chains. (`--flag-aaa` / `-FlagAaa` reports AAA presence as
an INFO finding, for teams that have chosen to drop it.)

**`trustscan` cannot cover compiled-in root stores.** Go, Node.js, uv, Electron,
Bun, and Rust `webpki-roots`/`rustls-webpki` bake their CA roots into the binary
- there is no cert file to scan, so a scanner can't detect them. For those, the
only valid check is *"is the runtime ≥ the patched version?"* - a version/patch
check, which is out of scope for this tool.

**It's a point-in-time, per-host inventory.** At fleet scale, feed the CSV/JSON
into your existing pipeline, or use `--rootfs` per image in CI.

## IOC data is self-verified

`emsign_iocs.json` (16 cert entries = 8 keys × two issuing paths, their SPKI
hashes, the compromised CA key-identifiers, and the affected roots) is
**generated and verified**, not transcribed. `tools/build_iocs.py` re-parses
every certificate, **recomputes each fingerprint**, cross-checks the serial, and
**reconfirms each key is weak by recovering its small scalar** before writing the
file.

```bash
# the upstream inputs are committed under tools/sources/, so this reproduces
# emsign_iocs.json byte-for-byte from a clean clone
python -I tools/build_iocs.py \
    tools/sources/impacted-intermediates.json \
    tools/sources/roots.json \
    emsign_iocs.json
```

(Isolated mode because the upstream tracker JSON is untrusted.) Upstream:
[emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/). Recovered
scalars match the independently published analysis.

## References

- Mozilla Security Blog - [Protecting Firefox users](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- Bugzilla [2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) (access-restricted)
- Scott Helme - [Eight Bits of Trust](https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/)
- Community tracker - [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/)

## Disclaimer

Defensive tooling for authorized use on systems you administer. The IOC set
reflects the incident as of the file's `generated` date; verify against primary
sources before acting. No warranty.
