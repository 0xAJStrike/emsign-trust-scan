#!/usr/bin/env python3
"""trustscan - find eMudhra/emSign compromised certificates in trust stores.

Following the October 2026 compromise of eMudhra/emSign intermediate CA private
keys, forged certificates chaining to those keys are trusted by anything that
still trusts the affected hierarchy -- and most non-browser trust stores do not
receive automatic distrust updates. This tool inventories the trust stores and
certificate collections reachable on a host and flags anything matching the
incident IOCs.

It matches a discovered certificate four ways:

  1. compromised_ca_cert     - the exact compromised intermediate (by cert SHA-256)
  2. compromised_key_reuse   - a different cert carrying a compromised *key*
                               (by SubjectPublicKeyInfo SHA-256; catches the
                               Sectigo cross-signs and any re-issue)
  3. issued_by_compromised_ca- a leaf/sub-CA whose AuthorityKeyIdentifier points
                               at a compromised intermediate (a forgeable cert)
  4. distrust_root_present   - an emSign root slated for distrust is present

The legitimate Sectigo root "AAA Certificate Services" is not flagged by default:
it cross-signed the bad intermediates, so it anchors their second trust path.
Mozilla and Chrome dropped it in April 2025 (15-year root-age policy), but
Windows, Apple, older Linux ca-certificates packages and many Java/appliance
keystores still trust it. --flag-aaa reports it as an INFO finding
(cross_sign_root_present) for teams deciding whether to remove it. Every run
ends with a one-line caveat about that path.

IOC data comes from emsign_iocs.json (next to this script, or --ioc-file),
which is generated and fingerprint-verified by tools/build_iocs.py.

Exit codes: 0 = clean (INFO-only results count as clean), 1 = at least one
finding, 2 = usage/IOC-load error.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import io
import json
import os
import sqlite3
import ssl
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs7, pkcs12

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".cert",
              ".p7b", ".p7c", ".p12", ".pfx", ".jks", ".keystore", ".truststore"}

# Passwords tried when opening a PKCS#12 trust store. "changeit" is the Java
# cacerts default; b"" / None cover the common no-password export.
_P12_PASSWORDS = (b"changeit", b"", None)
_JKS_MAGIC = b"\xfe\xed\xfe\xed"

# Printed once per run (not per finding): a scan of trust stores cannot prove a
# client rejects forged chains, because the compromised intermediates are also
# cross-signed by the legitimate AAA Certificate Services root. Mozilla and Chrome
# dropped that root in April 2025 (15-year root-age policy); Windows, Apple, older
# Linux ca-certificates packages and many Java/appliance keystores still trust it,
# so it is reported only on request (--flag-aaa), never by default.
AAA_CAVEAT = (
    "Note: this scan does not prove the host rejects forged chains. The compromised "
    "intermediates are also cross-signed by AAA Certificate Services, a legitimate root "
    "that Mozilla and Chrome dropped in April 2025 (15-year root-age policy) but that "
    "Windows, Apple, older Linux ca-certificates packages and many Java/appliance "
    "keystores still trust. This tool does not flag it by default (--flag-aaa reports "
    "it). A client that skips revocation can still accept a forged chain through it "
    "even with every emSign root gone. Full remediation needs the eight intermediate "
    "keys blocked by SPKI (as Chrome and Go do), the client patched, or revocation "
    "checking enabled."
)


# --------------------------------------------------------------------------- #
# IOC model
# --------------------------------------------------------------------------- #

@dataclass
class IOCSet:
    cert_index: dict               # cert_sha256 -> compromised cert entry
    spki_index: dict               # spki_sha256 -> compromised cert entry
    ski_set: set                   # subject key identifiers of compromised CAs
    distrust_cert_index: dict      # cert_sha256 -> root entry (action=review_distrust)
    distrust_spki_index: dict      # spki_sha256 -> root entry
    context_cert_index: dict       # cert_sha256 -> legitimate cross-sign root (AAA)
    context_spki_index: dict       # spki_sha256 -> legitimate cross-sign root (AAA)
    raw: dict
    flag_aaa: bool = False         # set by --flag-aaa; report AAA presence as INFO

    @classmethod
    def load(cls, path: Path) -> "IOCSet":
        data = json.loads(path.read_text(encoding="utf-8"))
        cert_index, spki_index = {}, {}
        for c in data.get("compromised_certs", []):
            cert_index[c["cert_sha256"].lower()] = c
            spki_index.setdefault(c["spki_sha256"].lower(), c)
        ski_set = {s.lower() for s in data.get("compromised_subject_key_identifiers", [])}
        distrust_cert_index, distrust_spki_index = {}, {}
        context_cert_index, context_spki_index = {}, {}
        for r in data.get("affected_roots", []):
            action = r.get("action")
            if action == "review_distrust":
                distrust_cert_index[r["cert_sha256"].lower()] = r
                distrust_spki_index[r["spki_sha256"].lower()] = r
            elif action == "legitimate_root_context":
                context_cert_index[r["cert_sha256"].lower()] = r
                context_spki_index[r["spki_sha256"].lower()] = r
        return cls(cert_index, spki_index, ski_set,
                   distrust_cert_index, distrust_spki_index,
                   context_cert_index, context_spki_index, data)


# --------------------------------------------------------------------------- #
# Discovered certs and findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    severity: str
    type: str
    source: str
    location: str
    subject: str
    serial: str
    cert_sha256: str
    spki_sha256: str
    matched_name: str = ""
    recovered_scalar: Optional[int] = None
    detail: str = ""


def _der_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _spki_sha256(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _aki_hex(cert: x509.Certificate) -> Optional[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        kid = ext.value.key_identifier
        return kid.hex() if kid else None
    except x509.ExtensionNotFound:
        return None


def _subject(cert: x509.Certificate) -> str:
    try:
        return cert.subject.rfc4514_string()
    except Exception:
        return "<unparseable subject>"


def match_cert(der: bytes, cert: x509.Certificate, iocs: IOCSet,
               source: str, location: str) -> list[Finding]:
    """Return every IOC finding this certificate triggers (possibly several).

    Never raises: real trust stores contain legacy/malformed certs (unsupported
    EC key encodings, non-RFC serials). The cert SHA-256 is always computable, so
    those certs are still matched exactly; only public-key-dependent checks are
    skipped when the key cannot be read.
    """
    findings: list[Finding] = []
    cert_fp = _der_sha256(der)

    try:
        spki_fp = _spki_sha256(cert)
    except Exception:
        spki_fp = None
    try:
        serial = format(cert.serial_number, "x")
        serial = ("0" + serial) if len(serial) % 2 else serial
    except Exception:
        serial = "?"
    subject = _subject(cert)

    base = dict(source=source, location=location, subject=subject, serial=serial,
                cert_sha256=cert_fp, spki_sha256=(spki_fp or ""))

    if cert_fp in iocs.cert_index:
        e = iocs.cert_index[cert_fp]
        findings.append(Finding(severity="CRITICAL", type="compromised_ca_cert",
                                matched_name=e["name"], recovered_scalar=e.get("recovered_scalar"),
                                detail=f"exact compromised intermediate (issued by {e.get('issued_by')})",
                                **base))
    elif spki_fp is not None and spki_fp in iocs.spki_index:
        e = iocs.spki_index[spki_fp]
        findings.append(Finding(severity="CRITICAL", type="compromised_key_reuse",
                                matched_name=e["name"], recovered_scalar=e.get("recovered_scalar"),
                                detail="different certificate carrying a compromised private key",
                                **base))

    # CRITICAL: the root's own key is intact, but the intermediate keys are
    # public -- so while this root is trusted, a forged chain for ANY domain
    # validates for every client that does not check revocation (which is
    # most non-browser clients, i.e. the stores this tool scans).
    if cert_fp in iocs.distrust_cert_index:
        e = iocs.distrust_cert_index[cert_fp]
        findings.append(Finding(severity="CRITICAL", type="distrust_root_present",
                                matched_name=e["name"],
                                detail="distrusted emSign root still trusted here; forged chains "
                                       "from the leaked intermediate keys validate against it. "
                                       "Remove it or update the bundle. This alone does not close "
                                       "the AAA cross-sign path: block the intermediate keys or "
                                       "enable revocation checking.",
                                **base))
    elif spki_fp is not None and spki_fp in iocs.distrust_spki_index:
        e = iocs.distrust_spki_index[spki_fp]
        findings.append(Finding(severity="CRITICAL", type="distrust_root_present",
                                matched_name=e["name"],
                                detail="distrusted emSign root key present under a different cert; "
                                       "forged chains from the leaked intermediate keys validate "
                                       "against it. Remove it. This alone does not close the AAA "
                                       "cross-sign path: block the intermediate keys or enable "
                                       "revocation checking.",
                                **base))

    # Opt-in (--flag-aaa): the legitimate cross-signing root (AAA Certificate
    # Services) anchors the intermediates' second trust path. INFO only: it is a
    # valid root that several major stores still trust, and dropping it is a
    # deliberate choice rather than a default remediation.
    if iocs.flag_aaa:
        ctx = iocs.context_cert_index.get(cert_fp)
        if ctx is None and spki_fp is not None:
            ctx = iocs.context_spki_index.get(spki_fp)
        if ctx is not None:
            findings.append(Finding(severity="INFO", type="cross_sign_root_present",
                                    matched_name=ctx["name"],
                                    detail="legitimate cross-signing root present; it anchors the "
                                           "compromised intermediates' second trust path. Mozilla and "
                                           "Chrome dropped it in 2025; Windows, Apple, older Linux "
                                           "bundles and many Java keystores still carry it. Not flagged "
                                           "by default; reported for teams deciding whether to remove it.",
                                    **base))

    # Leaf/sub issued by a compromised intermediate -- only if this cert isn't
    # itself one of the compromised CAs.
    if cert_fp not in iocs.cert_index and (spki_fp is None or spki_fp not in iocs.spki_index):
        try:
            aki = _aki_hex(cert)
        except Exception:
            aki = None
        if aki and aki.lower() in iocs.ski_set:
            findings.append(Finding(severity="HIGH", type="issued_by_compromised_ca",
                                    matched_name=aki,
                                    detail="certificate was issued by a compromised intermediate; "
                                           "treat as forgeable / replace",
                                    **base))
    return findings


# --------------------------------------------------------------------------- #
# Certificate sources
# --------------------------------------------------------------------------- #

def _pair(cert: x509.Certificate) -> tuple[bytes, x509.Certificate]:
    return (cert.public_bytes(Encoding.DER), cert)


def _add_der(out: list, der: bytes) -> None:
    try:
        out.append(_pair(x509.load_der_x509_certificate(der)))
    except Exception:
        pass


def _parse_jks(data: bytes) -> list[tuple[bytes, x509.Certificate]]:
    """Extract certificates from a JKS keystore (trusted-cert and key-chain
    entries). Pure stdlib; tolerant of truncation."""
    out: list[tuple[bytes, x509.Certificate]] = []
    try:
        pos = 8  # magic(4) + version(4)
        (count,) = struct.unpack_from(">I", data, pos); pos += 4
        for _ in range(count):
            (tag,) = struct.unpack_from(">I", data, pos); pos += 4
            (alen,) = struct.unpack_from(">H", data, pos); pos += 2 + alen  # alias
            pos += 8  # timestamp
            if tag == 1:                       # private-key entry
                (klen,) = struct.unpack_from(">I", data, pos); pos += 4 + klen
                (chain,) = struct.unpack_from(">I", data, pos); pos += 4
                for _ in range(chain):
                    (tlen,) = struct.unpack_from(">H", data, pos); pos += 2 + tlen
                    (clen,) = struct.unpack_from(">I", data, pos); pos += 4
                    _add_der(out, data[pos:pos + clen]); pos += clen
            elif tag == 2:                     # trusted-cert entry
                (tlen,) = struct.unpack_from(">H", data, pos); pos += 2 + tlen
                (clen,) = struct.unpack_from(">I", data, pos); pos += 4
                _add_der(out, data[pos:pos + clen]); pos += clen
            else:
                break
    except Exception:
        pass
    return out


def _certs_from_bytes(data: bytes) -> list[tuple[bytes, x509.Certificate]]:
    """Load certificates from any supported container: PEM/DER X.509, PKCS#7,
    PKCS#12, or JKS. Returns (der, cert) pairs; never raises."""
    try:
        certs = list(x509.load_pem_x509_certificates(data))
        if certs:
            return [_pair(c) for c in certs]
    except Exception:
        pass
    if data[:4] == _JKS_MAGIC:
        jks = _parse_jks(data)
        if jks:
            return jks
    try:
        return [_pair(x509.load_der_x509_certificate(data))]
    except Exception:
        pass
    for loader in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            certs = loader(data)
            if certs:
                return [_pair(c) for c in certs]
        except Exception:
            continue
    for pw in _P12_PASSWORDS:
        try:
            bundle = pkcs12.load_pkcs12(data, pw)
        except Exception:
            continue
        certs = [c.certificate for c in bundle.additional_certs]
        if bundle.cert is not None:
            certs.append(bundle.cert.certificate)
        if certs:
            return [_pair(c) for c in certs]
    return []


def scan_path(path: Path, iocs: IOCSet, source: str = "file") -> list[Finding]:
    findings: list[Finding] = []
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix.lower() in _CERT_EXTS:
                findings.extend(scan_path(child, iocs, source))
        return findings
    try:
        data = path.read_bytes()
    except OSError:
        return findings
    for der, cert in _certs_from_bytes(data):
        findings.extend(match_cert(der, cert, iocs, source=source, location=str(path)))
    return findings


def scan_certifi(iocs: IOCSet) -> list[Finding]:
    try:
        import certifi
    except Exception:
        return []
    return _scan_bundle_file(Path(certifi.where()), iocs, source="certifi")


# Well-known CA-bundle FILES shipped by tools/distros that update independently
# of the OS trust store (curl, FreeBSD, Homebrew, OS aggregate bundles, ...).
# Globs are expanded; only existing files are scanned. Compiled-in root stores
# (Go, Node, Electron, Bun, uv, rustls) have no file and are out of scope here.
_KNOWN_BUNDLE_GLOBS = (
    # OS aggregate bundles
    "/etc/ssl/certs/ca-certificates.crt",          # Debian/Ubuntu/Arch/Alpine aggregate
    "/etc/pki/tls/certs/ca-bundle.crt",            # RHEL/Fedora aggregate
    "/etc/ssl/cert.pem",                           # BSD/Alpine/LibreSSL
    "/etc/ssl/ca-bundle.pem",                      # SUSE
    "/var/lib/ca-certificates/ca-bundle.pem",      # SUSE
    "/usr/share/ca-certificates/",                 # Debian source certs (dir)
    # RHEL ca-trust extracted + admin anchors
    "/etc/pki/tls/cert.pem",                       # RHEL
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL extracted PEM
    "/etc/pki/ca-trust/extracted/java/cacerts",    # RHEL consolidated Java trust (JKS)
    "/etc/pki/ca-trust/source/anchors/",           # RHEL admin-added anchors (dir)
    # FreeBSD
    "/usr/local/share/certs/ca-root-nss.crt",      # FreeBSD ca_root_nss
    "/usr/local/etc/ssl/cert.pem",                 # FreeBSD/ports
    # Homebrew (Intel + Apple silicon)
    "/opt/homebrew/etc/ca-certificates/cert.pem",  # Homebrew (Apple silicon)
    "/usr/local/etc/ca-certificates/cert.pem",     # Homebrew (Intel)
    "/opt/homebrew/etc/openssl*/cert.pem",         # Homebrew openssl (Apple silicon)
    "/usr/local/etc/openssl*/cert.pem",            # Homebrew openssl (Intel)
    # MacPorts
    "/opt/local/etc/openssl/cert.pem",
    "/opt/local/etc/ssl/cert.pem",
    "/opt/local/share/curl/curl-ca-bundle.crt",
    # curl standalone / Git for Windows
    "/usr/local/share/curl/curl-ca-bundle.crt",
    r"C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
    r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
    # conda / Anaconda (each env ships its own ssl/cacert.pem)
    "$CONDA_PREFIX/ssl/cacert.pem",                # active conda env
    "/opt/conda/ssl/cacert.pem",
    "/opt/conda/envs/*/ssl/cacert.pem",
    "~/anaconda3/ssl/cacert.pem",
    "~/anaconda3/envs/*/ssl/cacert.pem",
    "~/miniconda3/ssl/cacert.pem",
    "~/miniconda3/envs/*/ssl/cacert.pem",
    "~/miniforge3/ssl/cacert.pem",
    "~/miniforge3/envs/*/ssl/cacert.pem",
    # AWS CLI v2 bundled botocore
    "/usr/local/aws-cli/v2/current/dist/awscli/botocore/cacert.pem",
    r"C:\Program Files\Amazon\AWSCLIV2\awscli\botocore\cacert.pem",
)


def _pip_vendored_certifi() -> Optional[Path]:
    try:
        import pip
        p = Path(pip.__file__).parent / "_vendor" / "certifi" / "cacert.pem"
        return p if p.is_file() else None
    except Exception:
        return None


def _known_bundle_paths() -> list[Path]:
    paths: list[Path] = []
    for pattern in _KNOWN_BUNDLE_GLOBS:
        expanded = os.path.expanduser(os.path.expandvars(pattern))  # ~ and $CONDA_PREFIX
        if "*" in expanded or "?" in expanded:
            paths.extend(Path(p) for p in glob.glob(expanded))
        else:
            paths.append(Path(expanded))
    vendored = _pip_vendored_certifi()
    if vendored:
        paths.append(vendored)
    return [p for p in paths if p.exists()]


def scan_known_bundles(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    for path in _known_bundle_paths():
        if path.is_dir():                       # e.g. anchors/, /usr/share/ca-certificates
            findings.extend(scan_path(path, iocs, source="bundle"))
        else:
            findings.extend(_scan_bundle_file(path, iocs, source="bundle"))
    return findings


def scan_env_bundles(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
        val = os.environ.get(var)
        if val and Path(val).is_file():
            findings.extend(_scan_bundle_file(Path(val), iocs, source=f"env:{var}"))
    for var in ("SSL_CERT_DIR",):
        val = os.environ.get(var)
        if val and Path(val).is_dir():
            findings.extend(scan_path(Path(val), iocs))
    return findings


def _scan_bundle_file(path: Path, iocs: IOCSet, source: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = path.read_bytes()
    except OSError:
        return findings
    for der, cert in _certs_from_bytes(data):
        findings.extend(match_cert(der, cert, iocs, source=source, location=str(path)))
    return findings


def scan_os_store(iocs: IOCSet) -> list[Finding]:
    if sys.platform.startswith("win"):
        return _scan_windows(iocs)
    if sys.platform == "darwin":
        return _scan_macos(iocs)
    return _scan_linux_dirs(iocs)


def _scan_windows(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    enum = getattr(ssl, "enum_certificates", None)
    if enum is None:
        return findings
    # ROOT/CA/MY plus TrustedPublisher and AuthRoot cover the code-signing path.
    for store in ("ROOT", "CA", "MY", "TrustedPublisher", "AuthRoot"):
        try:
            entries = enum(store)
        except Exception:
            continue
        for cert_bytes, enc, _trust in entries:
            if enc != "x509_asn":
                continue
            try:
                cert = x509.load_der_x509_certificate(cert_bytes)
            except Exception:
                continue
            findings.extend(match_cert(cert_bytes, cert, iocs,
                                       source="windows-store", location=f"Cert:\\{store}"))
    findings.extend(_scan_windows_gpo(iocs))
    return findings


def _der_from_cert_blob(blob: bytes) -> Optional[bytes]:
    """Extract the DER cert from a Windows serialized cert-property blob:
    repeated (propId:u32, reserved:u32, len:u32, data[len]); the cert is
    property id 0x20 (CERT_CERT_PROP_ID)."""
    i, n = 0, len(blob)
    while i + 12 <= n:
        prop_id = int.from_bytes(blob[i:i + 4], "little")
        length = int.from_bytes(blob[i + 8:i + 12], "little")
        start = i + 12
        if start + length > n:
            break
        if prop_id == 0x20:
            return blob[start:start + length]
        i = start + length
    return None


def _scan_windows_gpo(iocs: IOCSet) -> list[Finding]:
    """Group-Policy-pushed roots (LocalMachine) from the registry -- these are
    not returned by ssl.enum_certificates' per-store view."""
    try:
        import winreg
    except Exception:
        return []
    findings: list[Finding] = []
    for sub in (r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates",
                r"SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates",
                r"SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates"):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
        except OSError:
            continue
        try:
            idx = 0
            while True:
                try:
                    thumb = winreg.EnumKey(key, idx)
                except OSError:
                    break
                idx += 1
                try:
                    with winreg.OpenKey(key, thumb) as ck:
                        blob, _ = winreg.QueryValueEx(ck, "Blob")
                    der = _der_from_cert_blob(bytes(blob))
                    if der is None:
                        continue
                    cert = x509.load_der_x509_certificate(der)
                except Exception:
                    continue
                findings.extend(match_cert(der, cert, iocs,
                                           source="windows-gpo", location=f"HKLM\\{sub}\\{thumb}"))
        finally:
            winreg.CloseKey(key)
    return findings


def _scan_macos(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    for args in (["security", "find-certificate", "-a", "-p"],
                 ["security", "find-certificate", "-a", "-p",
                  "/System/Library/Keychains/SystemRootCertificates.keychain"]):
        try:
            out = subprocess.run(args, capture_output=True, timeout=30)
        except Exception:
            continue
        for der, cert in _certs_from_bytes(out.stdout):
            findings.extend(match_cert(der, cert, iocs,
                                       source="macos-keychain", location=" ".join(args[-1:])))
    return findings


def _scan_linux_dirs(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    for d in ("/etc/ssl/certs", "/usr/local/share/ca-certificates",
              "/etc/pki/tls/certs", "/etc/pki/ca-trust/extracted/pem"):
        p = Path(d)
        if p.exists():
            findings.extend(scan_path(p, iocs))
    # Android / AOSP (sys.platform is 'linux'): hash-named cert files per dir.
    for d in ("/system/etc/security/cacerts", "/apex/com.android.conscrypt/cacerts",
              "/data/misc/keychain/cacerts-added", "/data/misc/user/0/cacerts-added"):
        p = Path(d)
        if p.is_dir():
            findings.extend(_scan_dir_any(p, iocs, source="android-store"))
    return findings


# --- Java cacerts ---------------------------------------------------------- #

def _java_cacerts_paths() -> list[Path]:
    """Locate cacerts stores: $JAVA_HOME plus common JVM install roots."""
    homes: list[Path] = []
    if os.environ.get("JAVA_HOME"):
        homes.append(Path(os.environ["JAVA_HOME"]))
    for root in ("/usr/lib/jvm", "/opt/java", "/Library/Java/JavaVirtualMachines",
                 r"C:\Program Files\Java", r"C:\Program Files\Eclipse Adoptium",
                 r"C:\Program Files\Amazon Corretto", r"C:\Program Files\Microsoft"):
        base = Path(root)
        if base.is_dir():
            homes.extend(p for p in base.glob("*") if p.is_dir())
    out, seen = [], set()
    for h in homes:
        for rel in ("lib/security/cacerts", "jre/lib/security/cacerts",
                    "Contents/Home/lib/security/cacerts"):
            c = h / rel
            if c.is_file() and c not in seen:
                seen.add(c)
                out.append(c)
    return out


def scan_java_cacerts(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    for path in _java_cacerts_paths():
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for der, cert in _certs_from_bytes(data):
            findings.extend(match_cert(der, cert, iocs, source="java-cacerts", location=str(path)))
    return findings


# --- NSS cert9.db (Firefox / Thunderbird / Chrome-Linux) ------------------- #

def _nss_db_paths() -> list[Path]:
    home = Path.home()
    out: list[Path] = []
    for base in (home / ".mozilla" / "firefox", home / ".thunderbird",
                 home / "snap" / "firefox" / "common" / ".mozilla" / "firefox"):
        if base.is_dir():
            out.extend(base.glob("*/cert9.db"))
    for shared in (home / ".pki" / "nssdb" / "cert9.db",   # Chrome/Chromium on Linux
                   Path("/etc/pki/nssdb/cert9.db")):       # RHEL system-wide NSS
        if shared.is_file():
            out.append(shared)
    appdata = os.environ.get("APPDATA")
    if appdata:
        for sub in ("Mozilla/Firefox/Profiles", "Thunderbird/Profiles"):
            base = Path(appdata) / sub
            if base.is_dir():
                out.extend(base.glob("*/cert9.db"))
    return out


def _read_nss_db(path: Path) -> list[bytes]:
    """Extract DER certs from an NSS cert9.db. Certificates live in the
    nssPublic table; we take every blob there that parses as X.509."""
    ders: list[bytes] = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except Exception:
        return ders
    try:
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        if "nssPublic" not in tables:
            return ders
        for row in cur.execute('SELECT * FROM "nssPublic"'):
            for val in row:
                if isinstance(val, (bytes, bytearray)) and len(val) > 100:
                    try:
                        x509.load_der_x509_certificate(bytes(val))
                        ders.append(bytes(val))
                    except Exception:
                        pass
    except Exception:
        pass
    finally:
        con.close()
    return ders


def scan_nss(iocs: IOCSet) -> list[Finding]:
    findings: list[Finding] = []
    for db in _nss_db_paths():
        for der in _read_nss_db(db):
            try:
                cert = x509.load_der_x509_certificate(der)
            except Exception:
                continue
            findings.extend(match_cert(der, cert, iocs, source="nss", location=str(db)))
    return findings


# --- Container / rootfs / embedded-device mode ----------------------------- #

# Trust-store locations inside an image / firmware rootfs (relative to its root).
_ROOTFS_CERT_DIRS = (
    "etc/ssl/certs", "usr/local/share/ca-certificates", "etc/pki/tls/certs",
    "etc/pki/ca-trust/extracted/pem", "usr/share/ca-certificates",
    "var/lib/ca-certificates/pem", "etc/ca-certificates",
)
_ROOTFS_CERT_FILES = (
    "etc/ssl/certs/ca-certificates.crt", "etc/pki/tls/certs/ca-bundle.crt",
    "etc/ssl/cert.pem", "etc/pki/tls/cert.pem", "etc/ssl/ca-bundle.pem",
    "var/lib/ca-certificates/ca-bundle.pem",
    "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "etc/pki/ca-trust/extracted/java/cacerts",   # JKS
)
# Android / AOSP IoT: one cert per file, hash-named (e.g. a1b2c3d4.0) -> scan all.
_ANDROID_CERT_DIRS = (
    "system/etc/security/cacerts", "apex/com.android.conscrypt/cacerts",
    "data/misc/keychain/cacerts-added", "data/misc/user/0/cacerts-added",
)


def _scan_dir_any(path: Path, iocs: IOCSet, source: str) -> list[Finding]:
    """Scan every file in a directory regardless of extension (Android stores
    each trusted cert as a hash-named file like a1b2c3d4.0, no cert extension)."""
    findings: list[Finding] = []
    try:
        children = sorted(path.rglob("*"))
    except OSError:
        return findings
    for child in children:
        try:
            if child.is_file():
                findings.extend(_scan_bundle_file(child, iocs, source))
        except OSError:
            continue
    return findings


def _scan_trust_paths(root: Path, iocs: IOCSet, source: str) -> list[Finding]:
    """Scan the well-known trust-store files/dirs under a rootfs prefix."""
    findings: list[Finding] = []
    for d in _ROOTFS_CERT_DIRS:
        p = root / d
        if p.is_dir():
            findings.extend(scan_path(p, iocs, source=source))
    for f in _ROOTFS_CERT_FILES:
        p = root / f
        if p.is_file():
            findings.extend(_scan_bundle_file(p, iocs, source))
    for d in _ANDROID_CERT_DIRS:
        p = root / d
        if p.is_dir():
            findings.extend(_scan_dir_any(p, iocs, source))
    return findings


def scan_rootfs(root: Path, iocs: IOCSet) -> list[Finding]:
    """Scan the trust stores inside one extracted image / firmware rootfs."""
    findings = _scan_trust_paths(root, iocs, source="rootfs")
    for cacerts in root.glob("**/lib/security/cacerts"):   # Java keystores anywhere
        try:
            data = cacerts.read_bytes()
        except OSError:
            continue
        for der, cert in _certs_from_bytes(data):
            findings.extend(match_cert(der, cert, iocs, source="rootfs-java", location=str(cacerts)))
    return findings


# Host container storage: each layer's changes live in a 'diff' dir (containerd
# uses 'fs'). We scan 'diff' only, not the assembled 'merged' mount: 'merged'
# re-counts every running container's full union (shared base-image roots over
# and over), while 'diff' reports each layer's certs once, at rest, and overlay2
# already stores a shared layer a single time. The storage dirs are root-only, so
# unreadable layers are skipped. Only the containerd *overlayfs* snapshotter is
# matched (native/btrfs/zfs/stargz use different layouts).
_CONTAINER_LAYER_GLOBS = (
    "/var/lib/docker/overlay2/*/diff",                        # Docker
    "/var/lib/containers/storage/overlay/*/diff",             # podman (root)
    "~/.local/share/containers/storage/overlay/*/diff",       # podman (rootless, scanning user)
    "/home/*/.local/share/containers/storage/overlay/*/diff", # podman (rootless, other users)
    "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs",  # containerd
)


def _scan_layer_bundles(root: Path, iocs: IOCSet, source: str) -> list[Finding]:
    """Scan only the aggregate bundle *files* under a container layer (not the
    per-cert dir walk). The aggregate (ca-certificates.crt / tls-ca-bundle.pem) is
    the effective trust store, a regular file, and avoids the dir walk's
    aggregate+per-cert+symlink triple-count. Symlinks that resolve outside the
    layer (absolute links onto the host fs) are skipped so we never read a host
    file and mislabel it as the container's."""
    findings: list[Finding] = []
    root_real = os.path.realpath(root)
    for f in _ROOTFS_CERT_FILES:
        p = root / f
        try:
            if not p.is_file():
                continue
            if not os.path.realpath(p).startswith(root_real + os.sep):
                continue  # symlink escapes the layer onto the host
        except OSError:
            continue
        findings.extend(_scan_bundle_file(p, iocs, source))
    return findings


def scan_containers(iocs: IOCSet) -> list[Finding]:
    """Scan Docker / podman / containerd container layers on the host for the CA
    bundles they ship. Opt-in (`--source containers`); needs root for the storage
    dirs. The location names the layer, so you can map a hit back to an image."""
    findings: list[Finding] = []
    for pattern in _CONTAINER_LAYER_GLOBS:
        for layer in glob.glob(os.path.expanduser(pattern)):
            lp = Path(layer)
            try:
                if lp.is_dir():
                    findings.extend(_scan_layer_bundles(lp, iocs, source="container"))
            except OSError:
                continue
    return findings


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        # Same cert at the same location is one finding regardless of which
        # source found it (e.g. a bundle hit by both the os and bundles scans).
        key = (f.type, f.location, f.cert_sha256)
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.type, f.location))
    return out


def format_text(findings: list[Finding], ioc_generated: str = "") -> str:
    stamp = f" (IOC data generated {ioc_generated})" if ioc_generated else ""
    if not findings:
        return ("No eMudhra/emSign compromised certificates found in the scanned "
                f"stores.{stamp}\n\n{AAA_CAVEAT}")
    lines = []
    for f in findings:
        lines.append(f"[{f.severity}] {f.type}  ({f.source})")
        lines.append(f"    location : {f.location}")
        lines.append(f"    subject  : {f.subject}")
        lines.append(f"    serial   : {f.serial}")
        lines.append(f"    cert     : {f.cert_sha256}")
        lines.append(f"    spki     : {f.spki_sha256}")
        if f.matched_name:
            extra = f"    matched  : {f.matched_name}"
            if f.recovered_scalar is not None:
                extra += f"  (private key = {f.recovered_scalar})"
            lines.append(extra)
        lines.append(f"    note     : {f.detail}")
        lines.append("")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if s in counts)
    lines.append(f"Summary: {len(findings)} finding(s): {summary}{stamp}")
    lines.append("")
    lines.append(AAA_CAVEAT)
    return "\n".join(lines)


def format_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    cols = ["severity", "type", "source", "location", "subject", "serial",
            "cert_sha256", "spki_sha256", "matched_name", "recovered_scalar", "detail"]
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    for f in findings:
        w.writerow(asdict(f))
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def run_scan(paths: list[str], iocs: IOCSet, sources: set[str],
             rootfs: Iterable[str] = ()) -> list[Finding]:
    findings: list[Finding] = []
    if "os" in sources:
        findings.extend(scan_os_store(iocs))
    if "certifi" in sources:
        findings.extend(scan_certifi(iocs))
    if "bundles" in sources:
        findings.extend(scan_known_bundles(iocs))
    if "env" in sources:
        findings.extend(scan_env_bundles(iocs))
    if "java" in sources:
        findings.extend(scan_java_cacerts(iocs))
    if "nss" in sources:
        findings.extend(scan_nss(iocs))
    if "containers" in sources:
        findings.extend(scan_containers(iocs))
    if "paths" in sources:
        for p in paths:
            findings.extend(scan_path(Path(p), iocs))
    for r in rootfs:
        findings.extend(scan_rootfs(Path(r), iocs))
    return dedupe(findings)


def _silence_legacy_cert_warnings() -> None:
    """Real trust stores hold legacy / non-conformant certs that trip warnings
    (deprecated serials, over-length name attributes like a 16-char countryName);
    the scanner handles them, so keep that noise off stderr."""
    import warnings
    try:
        from cryptography.utils import CryptographyDeprecationWarning
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    except Exception:
        pass
    warnings.filterwarnings("ignore", message=r"Attribute's length must be",
                            category=UserWarning)


def main(argv: Optional[list[str]] = None) -> int:
    _silence_legacy_cert_warnings()
    parser = argparse.ArgumentParser(
        prog="trustscan",
        description="Inventory trust stores for eMudhra/emSign compromised certificates.")
    parser.add_argument("paths", nargs="*",
                        help="extra cert files/directories to scan")
    parser.add_argument("--ioc-file", default=None,
                        help="IOC JSON (default: emsign_iocs.json beside this script)")
    parser.add_argument("--source", action="append",
                        choices=["os", "certifi", "bundles", "env", "java", "nss",
                                 "containers", "paths", "all"],
                        help="which sources to scan (repeatable; default all applicable; "
                             "'containers' scans Docker/podman/containerd layers and needs root)")
    parser.add_argument("--rootfs", action="append", default=[],
                        help="scan trust stores inside an extracted image rootfs (repeatable)")
    parser.add_argument("--flag-aaa", action="store_true",
                        help="also report AAA Certificate Services (the legitimate cross-sign "
                             "root) as an INFO finding when present")
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text")
    args = parser.parse_args(argv)

    ioc_path = Path(args.ioc_file) if args.ioc_file else Path(__file__).with_name("emsign_iocs.json")
    try:
        iocs = IOCSet.load(ioc_path)
    except Exception as exc:
        print(f"error: could not load IOC file {ioc_path}: {exc}", file=sys.stderr)
        return 2
    iocs.flag_aaa = args.flag_aaa

    # A mistyped path must never read as "clean": warn on each missing target,
    # and refuse to run if nothing the user asked for exists.
    requested = list(args.paths) + list(args.rootfs)
    missing = [p for p in requested if not Path(p).exists()]
    for m in missing:
        print(f"warning: path not found, skipped: {m}", file=sys.stderr)
    if requested and len(missing) == len(requested):
        print("error: none of the requested paths exist", file=sys.stderr)
        return 2

    chosen = set(args.source or ["all"])
    if "all" in chosen:
        chosen = {"os", "certifi", "bundles", "env", "java", "nss", "paths"}
    # Only scan paths if some were given.
    if not args.paths:
        chosen.discard("paths")

    findings = run_scan(args.paths, iocs, chosen, rootfs=args.rootfs)
    generated = str(iocs.raw.get("generated", "")) or "unknown"

    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
        print(f"IOC data generated: {generated}", file=sys.stderr)
        print(AAA_CAVEAT, file=sys.stderr)
    elif args.format == "csv":
        print(format_csv(findings), end="")
        print(f"IOC data generated: {generated}", file=sys.stderr)
        print(AAA_CAVEAT, file=sys.stderr)
    else:
        print(format_text(findings, generated))

    # INFO-only findings (e.g. --flag-aaa surfacing AAA) are not failures.
    return 1 if any(f.severity != "INFO" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
