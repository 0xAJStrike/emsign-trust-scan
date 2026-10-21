"""Tests for trustscan.

Two layers:
  * synthetic-IOC unit tests exercise all four match types (and prove the
    legitimate Sectigo-style root is NOT flagged) with fully controlled data;
  * real-IOC integration tests run against the shipped emsign_iocs.json, using
    the fact that a cert built from the known weak scalar d=4 reproduces the
    real EM OV TLS CA - G3C public key (same SPKI).
"""

import datetime
import hashlib
import json
import sqlite3
import struct
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, NoEncryption, PublicFormat, pkcs7, pkcs12)
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import trustscan as ts  # noqa: E402

SHIPPED_IOC = Path(__file__).resolve().parent.parent / "emsign_iocs.json"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def build_cert(priv, cn, serial=0x01, *, issuer_priv=None, issuer_cn=None,
               ski=None, aki_keyid=None):
    issuer_priv = issuer_priv or priv
    issuer_cn = issuer_cn or cn
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(priv.public_key()).serial_number(serial)
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)))
    if ski is not None:
        b = b.add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
    if aki_keyid is not None:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier(key_identifier=aki_keyid,
                                        authority_cert_issuer=None,
                                        authority_cert_serial_number=None),
            critical=False)
    return b.sign(issuer_priv, hashes.SHA256())


def der_sha(cert):
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def spki_sha(cert):
    return hashlib.sha256(cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def write_ioc(tmp_path, compromised=None, roots=None, skis=None):
    data = {
        "schema": "emsign-ioc/1",
        "compromised_certs": compromised or [],
        "compromised_spki_sha256": sorted({c["spki_sha256"] for c in (compromised or [])}),
        "compromised_subject_key_identifiers": skis or [],
        "affected_roots": roots or [],
    }
    p = tmp_path / "ioc.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return ts.IOCSet.load(p)


def pem_bytes(cert):
    return cert.public_bytes(Encoding.PEM)


# --------------------------------------------------------------------------- #
# synthetic IOC: the four match types
# --------------------------------------------------------------------------- #

def test_exact_compromised_cert_match(tmp_path):
    priv = ec.generate_private_key(ec.SECP384R1())
    cert = build_cert(priv, "EM BAD CA", serial=0xABCD)
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(cert),
        "spki_sha256": spki_sha(cert), "recovered_scalar": 123}])
    f = ts.match_cert(cert.public_bytes(Encoding.DER), cert, iocs, "test", "loc")
    assert len(f) == 1
    assert f[0].severity == "CRITICAL" and f[0].type == "compromised_ca_cert"
    assert f[0].recovered_scalar == 123


def test_spki_reuse_match_different_cert(tmp_path):
    priv = ec.generate_private_key(ec.SECP384R1())
    original = build_cert(priv, "EM BAD CA", serial=1)
    # Different cert (new serial + subject) but the SAME key.
    reissued = build_cert(priv, "EM BAD CA REISSUE", serial=2)
    assert der_sha(original) != der_sha(reissued)
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(original),
        "spki_sha256": spki_sha(original), "recovered_scalar": 7}])
    f = ts.match_cert(reissued.public_bytes(Encoding.DER), reissued, iocs, "test", "loc")
    assert len(f) == 1
    assert f[0].type == "compromised_key_reuse" and f[0].severity == "CRITICAL"


def test_issued_by_compromised_ca_via_aki(tmp_path):
    ski = bytes.fromhex("aabbccddeeff00112233445566778899aabbccdd")
    leaf_priv = ec.generate_private_key(ec.SECP256R1())
    leaf = build_cert(leaf_priv, "server.example", serial=5, aki_keyid=ski)
    iocs = write_ioc(tmp_path, skis=[ski.hex()])
    f = ts.match_cert(leaf.public_bytes(Encoding.DER), leaf, iocs, "test", "loc")
    assert len(f) == 1
    assert f[0].type == "issued_by_compromised_ca" and f[0].severity == "HIGH"


def test_distrust_root_flagged_legitimate_root_not(tmp_path):
    distrust_priv = ec.generate_private_key(ec.SECP384R1())
    distrust_root = build_cert(distrust_priv, "emSign Root TLS CA - G3")
    legit_priv = ec.generate_private_key(ec.SECP384R1())
    legit_root = build_cert(legit_priv, "AAA Certificate Services")
    iocs = write_ioc(tmp_path, roots=[
        {"name": "emSign Root TLS CA - G3", "cert_sha256": der_sha(distrust_root),
         "spki_sha256": spki_sha(distrust_root), "action": "review_distrust"},
        {"name": "AAA Certificate Services", "cert_sha256": der_sha(legit_root),
         "spki_sha256": spki_sha(legit_root), "action": "legitimate_root_context"},
    ])
    f_distrust = ts.match_cert(distrust_root.public_bytes(Encoding.DER), distrust_root,
                               iocs, "test", "loc")
    assert len(f_distrust) == 1 and f_distrust[0].type == "distrust_root_present"
    assert f_distrust[0].severity == "CRITICAL"
    # The legitimate Sectigo-style root must produce NO finding.
    f_legit = ts.match_cert(legit_root.public_bytes(Encoding.DER), legit_root,
                            iocs, "test", "loc")
    assert f_legit == []


def test_clean_cert_no_findings(tmp_path):
    priv = ec.generate_private_key(ec.SECP384R1())
    cert = build_cert(priv, "totally.legit")
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": "00" * 32, "spki_sha256": "11" * 32}])
    f = ts.match_cert(cert.public_bytes(Encoding.DER), cert, iocs, "test", "loc")
    assert f == []


# --------------------------------------------------------------------------- #
# source scanning
# --------------------------------------------------------------------------- #

def test_scan_directory_pem_and_der(tmp_path):
    priv = ec.generate_private_key(ec.SECP384R1())
    bad = build_cert(priv, "EM BAD CA", serial=9)
    good = build_cert(ec.generate_private_key(ec.SECP384R1()), "good")
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(bad), "spki_sha256": spki_sha(bad)}])
    store = tmp_path / "store"
    (store / "sub").mkdir(parents=True)
    (store / "bad.pem").write_bytes(pem_bytes(bad))
    (store / "sub" / "good.crt").write_bytes(pem_bytes(good))
    (store / "bad.der").write_bytes(bad.public_bytes(Encoding.DER))
    (store / "notes.txt").write_bytes(b"ignore me")
    findings = ts.scan_path(store, iocs)
    # bad.pem and bad.der both match; dedupe happens at run_scan level, so here 2.
    assert all(f.type == "compromised_ca_cert" for f in findings)
    assert len(findings) == 2


def test_env_bundle_scanned(tmp_path, monkeypatch):
    priv = ec.generate_private_key(ec.SECP384R1())
    bad = build_cert(priv, "EM BAD CA", serial=9)
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(bad), "spki_sha256": spki_sha(bad)}])
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(pem_bytes(bad))
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(bundle))
    findings = ts.scan_env_bundles(iocs)
    assert any(f.source == "env:NODE_EXTRA_CA_CERTS" for f in findings)


def test_os_store_scan_runs(tmp_path):
    """Smoke test: scanning the real OS store must not raise and returns a list."""
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "x", "cert_sha256": "00" * 32, "spki_sha256": "11" * 32}])
    result = ts.scan_os_store(iocs)
    assert isinstance(result, list)


def test_der_from_cert_blob_roundtrip(tmp_path):
    """The Windows serialized-cert-property blob parser extracts the DER cert."""
    bad, _ = _bad_cert_and_ioc(tmp_path)
    der = bad.public_bytes(Encoding.DER)

    def element(prop_id, data):
        return struct.pack("<III", prop_id, 0, len(data)) + data

    blob = element(3, b"\x00" * 20) + element(0x20, der) + element(4, b"\x00" * 16)
    assert ts._der_from_cert_blob(blob) == der
    assert ts._der_from_cert_blob(b"\x00" * 8) is None  # too short / no cert property


def test_dedupe_collapses_duplicates(tmp_path):
    priv = ec.generate_private_key(ec.SECP384R1())
    bad = build_cert(priv, "EM BAD CA", serial=9)
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(bad), "spki_sha256": spki_sha(bad)}])
    f = ts.match_cert(bad.public_bytes(Encoding.DER), bad, iocs, "src", "same")
    doubled = ts.dedupe(f + f)
    assert len(doubled) == 1


def test_dedupe_ignores_source(tmp_path):
    """The same cert at the same location found by two sources is ONE finding
    (e.g. /etc/ssl/certs/ca-certificates.crt hit by both os and bundles)."""
    priv = ec.generate_private_key(ec.SECP384R1())
    bad = build_cert(priv, "EM BAD CA", serial=9)
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(bad), "spki_sha256": spki_sha(bad)}])
    der = bad.public_bytes(Encoding.DER)
    a = ts.match_cert(der, bad, iocs, "file", "/same/location.crt")
    b = ts.match_cert(der, bad, iocs, "bundle", "/same/location.crt")
    assert len(ts.dedupe(a + b)) == 1


# --------------------------------------------------------------------------- #
# CLI / output
# --------------------------------------------------------------------------- #

def test_cli_exit_and_csv(tmp_path, capsys):
    priv = ec.generate_private_key(ec.SECP384R1())
    bad = build_cert(priv, "EM BAD CA", serial=9)
    ioc = tmp_path / "ioc.json"
    ioc.write_text(json.dumps({
        "compromised_certs": [{"name": "EM BAD CA", "cert_sha256": der_sha(bad),
                               "spki_sha256": spki_sha(bad), "recovered_scalar": 4}],
        "compromised_spki_sha256": [spki_sha(bad)],
        "compromised_subject_key_identifiers": [],
        "affected_roots": []}), encoding="utf-8")
    certfile = tmp_path / "bad.pem"
    certfile.write_bytes(pem_bytes(bad))
    code = ts.main([str(certfile), "--ioc-file", str(ioc),
                    "--source", "paths", "--format", "csv"])
    out = capsys.readouterr().out
    assert code == 1
    assert "compromised_ca_cert" in out
    assert out.splitlines()[0].startswith("severity,type,source")


def test_cli_clean_exit_zero(tmp_path, capsys):
    good = build_cert(ec.generate_private_key(ec.SECP384R1()), "good")
    ioc = tmp_path / "ioc.json"
    ioc.write_text(json.dumps({
        "compromised_certs": [{"name": "x", "cert_sha256": "00" * 32,
                               "spki_sha256": "11" * 32}],
        "compromised_spki_sha256": ["11" * 32],
        "compromised_subject_key_identifiers": [], "affected_roots": []}),
        encoding="utf-8")
    certfile = tmp_path / "good.pem"
    certfile.write_bytes(pem_bytes(good))
    code = ts.main([str(certfile), "--ioc-file", str(ioc), "--source", "paths"])
    assert code == 0
    assert "No eMudhra/emSign compromised" in capsys.readouterr().out


def test_cli_bad_ioc_file_exit_two(tmp_path, capsys):
    code = ts.main(["--ioc-file", str(tmp_path / "nope.json")])
    assert code == 2


def test_cli_missing_path_never_reports_clean(tmp_path, capsys):
    """A typo'd path must not produce a false all-clear (exit 0)."""
    ioc = tmp_path / "ioc.json"
    ioc.write_text(json.dumps({
        "generated": "2026-10-21",
        "compromised_certs": [{"name": "x", "cert_sha256": "00" * 32,
                               "spki_sha256": "11" * 32}],
        "compromised_spki_sha256": ["11" * 32],
        "compromised_subject_key_identifiers": [], "affected_roots": []}),
        encoding="utf-8")
    code = ts.main([str(tmp_path / "does-not-exist.pem"),
                    "--ioc-file", str(ioc), "--source", "paths"])
    captured = capsys.readouterr()
    assert code == 2
    assert "not found" in captured.err
    assert "No eMudhra/emSign" not in captured.out


def test_text_output_shows_ioc_generated_date(tmp_path, capsys):
    good = build_cert(ec.generate_private_key(ec.SECP384R1()), "good")
    ioc = tmp_path / "ioc.json"
    ioc.write_text(json.dumps({
        "generated": "2026-10-21",
        "compromised_certs": [{"name": "x", "cert_sha256": "00" * 32,
                               "spki_sha256": "11" * 32}],
        "compromised_spki_sha256": ["11" * 32],
        "compromised_subject_key_identifiers": [], "affected_roots": []}),
        encoding="utf-8")
    certfile = tmp_path / "good.pem"
    certfile.write_bytes(pem_bytes(good))
    code = ts.main([str(certfile), "--ioc-file", str(ioc), "--source", "paths"])
    assert code == 0
    assert "IOC data generated 2026-10-21" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# AAA cross-sign caveat + opt-in --flag-aaa
# --------------------------------------------------------------------------- #

def _aaa_ioc(tmp_path, aaa):
    """IOC file whose only affected_root is AAA (legitimate cross-sign root)."""
    ioc = tmp_path / "ioc.json"
    ioc.write_text(json.dumps({
        "generated": "2026-10-21",
        "compromised_certs": [], "compromised_spki_sha256": [],
        "compromised_subject_key_identifiers": [],
        "affected_roots": [{"name": "AAA Certificate Services",
                            "cert_sha256": der_sha(aaa), "spki_sha256": spki_sha(aaa),
                            "action": "legitimate_root_context"}]}), encoding="utf-8")
    return ioc


def test_aaa_not_flagged_by_default_but_info_with_flag(tmp_path):
    aaa = build_cert(ec.generate_private_key(ec.SECP384R1()), "AAA Certificate Services")
    iocs = write_ioc(tmp_path, roots=[{
        "name": "AAA Certificate Services", "cert_sha256": der_sha(aaa),
        "spki_sha256": spki_sha(aaa), "action": "legitimate_root_context"}])
    der = aaa.public_bytes(Encoding.DER)
    assert ts.match_cert(der, aaa, iocs, "s", "l") == []          # default: silent
    iocs.flag_aaa = True
    f = ts.match_cert(der, aaa, iocs, "s", "l")
    assert len(f) == 1
    assert f[0].type == "cross_sign_root_present" and f[0].severity == "INFO"


def test_cli_flag_aaa_is_info_and_exits_zero(tmp_path, capsys):
    aaa = build_cert(ec.generate_private_key(ec.SECP384R1()), "AAA Certificate Services")
    ioc = _aaa_ioc(tmp_path, aaa)
    f = tmp_path / "aaa.pem"
    f.write_bytes(pem_bytes(aaa))
    # default: AAA present, no --flag-aaa -> clean, exit 0
    assert ts.main([str(f), "--ioc-file", str(ioc), "--source", "paths"]) == 0
    assert "cross_sign_root_present" not in capsys.readouterr().out
    # opt-in: INFO finding, still exit 0 (INFO is not a failure)
    code = ts.main([str(f), "--ioc-file", str(ioc), "--source", "paths", "--flag-aaa"])
    out = capsys.readouterr().out
    assert code == 0
    assert "cross_sign_root_present" in out and "INFO" in out


def test_aaa_caveat_printed_once_on_clean_scan(tmp_path, capsys):
    good = build_cert(ec.generate_private_key(ec.SECP384R1()), "good")
    ioc = _aaa_ioc(tmp_path, build_cert(ec.generate_private_key(ec.SECP384R1()), "AAA"))
    certfile = tmp_path / "good.pem"
    certfile.write_bytes(pem_bytes(good))
    ts.main([str(certfile), "--ioc-file", str(ioc), "--source", "paths"])
    out = capsys.readouterr().out
    assert "does not prove the host rejects forged chains" in out
    assert out.count("AAA Certificate Services") == 1   # footer only, not per-row


def test_caveat_goes_to_stderr_in_machine_formats(tmp_path, capsys):
    """json/csv stdout must stay parseable: the caveat is stderr-only there."""
    good = build_cert(ec.generate_private_key(ec.SECP384R1()), "good")
    ioc = _aaa_ioc(tmp_path, build_cert(ec.generate_private_key(ec.SECP384R1()), "AAA"))
    certfile = tmp_path / "good.pem"
    certfile.write_bytes(pem_bytes(good))
    for fmt in ("json", "csv"):
        ts.main([str(certfile), "--ioc-file", str(ioc), "--source", "paths", "--format", fmt])
        captured = capsys.readouterr()
        assert "does not prove the host rejects forged chains" not in captured.out
        assert "does not prove the host rejects forged chains" in captured.err
    # and json stdout is exactly a JSON document
    ts.main([str(certfile), "--ioc-file", str(ioc), "--source", "paths", "--format", "json"])
    assert json.loads(capsys.readouterr().out) == []


# --------------------------------------------------------------------------- #
# integration against the shipped IOC file
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SHIPPED_IOC.exists(), reason="emsign_iocs.json not built")
def test_real_ioc_detects_weak_scalar_key():
    """A cert built from the known weak scalar d=4 reuses the real G3C key."""
    iocs = ts.IOCSet.load(SHIPPED_IOC)
    priv = ec.derive_private_key(4, ec.SECP384R1())
    cert = build_cert(priv, "forged.example", serial=0x99)
    f = ts.match_cert(cert.public_bytes(Encoding.DER), cert, iocs, "test", "loc")
    assert len(f) == 1
    assert f[0].type == "compromised_key_reuse"
    assert f[0].matched_name == "EM OV TLS CA - G3C"
    assert f[0].recovered_scalar == 4


@pytest.mark.skipif(not SHIPPED_IOC.exists(), reason="emsign_iocs.json not built")
def test_real_ioc_detects_leaf_issued_by_compromised_ca():
    iocs = ts.IOCSet.load(SHIPPED_IOC)
    real_ski = iocs.raw["compromised_subject_key_identifiers"][0]
    leaf = build_cert(ec.generate_private_key(ec.SECP256R1()), "leaf.example",
                      serial=0x77, aki_keyid=bytes.fromhex(real_ski))
    f = ts.match_cert(leaf.public_bytes(Encoding.DER), leaf, iocs, "test", "loc")
    assert any(x.type == "issued_by_compromised_ca" and x.severity == "HIGH" for x in f)


# --------------------------------------------------------------------------- #
# container formats: PKCS#7, PKCS#12, JKS
# --------------------------------------------------------------------------- #

def _make_jks(cert_ders):
    """Build a minimal JKS keystore with trusted-cert entries (dependency-free)."""
    buf = b"\xfe\xed\xfe\xed" + struct.pack(">I", 2) + struct.pack(">I", len(cert_ders))
    for i, der in enumerate(cert_ders):
        alias = f"alias{i}".encode()
        ctype = b"X.509"
        buf += struct.pack(">I", 2)                       # tag: trusted cert
        buf += struct.pack(">H", len(alias)) + alias
        buf += struct.pack(">Q", 0)                       # timestamp
        buf += struct.pack(">H", len(ctype)) + ctype
        buf += struct.pack(">I", len(der)) + der
    return buf + b"\x00" * 20                              # (ignored) digest trailer


def _bad_cert_and_ioc(tmp_path):
    priv = ec.generate_private_key(ec.SECP384R1())
    bad = build_cert(priv, "EM BAD CA", serial=0x42)
    iocs = write_ioc(tmp_path, compromised=[{
        "name": "EM BAD CA", "cert_sha256": der_sha(bad), "spki_sha256": spki_sha(bad)}])
    return bad, iocs


def test_parse_pkcs7_der_and_pem(tmp_path):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    for enc in (Encoding.DER, Encoding.PEM):
        blob = pkcs7.serialize_certificates([bad], enc)
        pairs = ts._certs_from_bytes(blob)
        assert any(der_sha(c) == der_sha(bad) for _, c in pairs)


def test_parse_pkcs12_with_and_without_password(tmp_path):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    protected = pkcs12.serialize_key_and_certificates(
        b"t", None, None, [bad], BestAvailableEncryption(b"changeit"))
    plain = pkcs12.serialize_key_and_certificates(b"t", None, None, [bad], NoEncryption())
    for blob in (protected, plain):
        pairs = ts._certs_from_bytes(blob)
        assert any(der_sha(c) == der_sha(bad) for _, c in pairs)


def test_parse_jks(tmp_path):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    good = build_cert(ec.generate_private_key(ec.SECP384R1()), "good")
    jks = _make_jks([bad.public_bytes(Encoding.DER), good.public_bytes(Encoding.DER)])
    pairs = ts._certs_from_bytes(jks)
    shas = {der_sha(c) for _, c in pairs}
    assert der_sha(bad) in shas and der_sha(good) in shas


def test_scan_path_detects_p12_and_jks_files(tmp_path):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    (tmp_path / "store.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"t", None, None, [bad], BestAvailableEncryption(b"changeit")))
    (tmp_path / "store.jks").write_bytes(_make_jks([bad.public_bytes(Encoding.DER)]))
    findings = ts.scan_path(tmp_path, iocs)
    assert len(findings) == 2
    assert all(f.type == "compromised_ca_cert" for f in findings)


# --------------------------------------------------------------------------- #
# known CA-bundle files (data-driven)
# --------------------------------------------------------------------------- #

def test_scan_known_bundles(tmp_path, monkeypatch):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    bundle = tmp_path / "ca-root-nss.crt"
    bundle.write_bytes(pem_bytes(bad))
    monkeypatch.setattr(ts, "_KNOWN_BUNDLE_GLOBS", (str(bundle), str(tmp_path / "missing.crt")))
    monkeypatch.setattr(ts, "_pip_vendored_certifi", lambda: None)
    findings = ts.scan_known_bundles(iocs)
    assert len(findings) == 1
    assert findings[0].source == "bundle" and findings[0].type == "compromised_ca_cert"


def test_known_bundle_paths_filters_missing(monkeypatch):
    monkeypatch.setattr(ts, "_KNOWN_BUNDLE_GLOBS", ("/no/such/path/ca.crt",))
    monkeypatch.setattr(ts, "_pip_vendored_certifi", lambda: None)
    assert ts._known_bundle_paths() == []


# --------------------------------------------------------------------------- #
# Java cacerts source
# --------------------------------------------------------------------------- #

def test_scan_java_cacerts_via_java_home(tmp_path, monkeypatch):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    home = tmp_path / "jdk"
    (home / "lib" / "security").mkdir(parents=True)
    (home / "lib" / "security" / "cacerts").write_bytes(
        _make_jks([bad.public_bytes(Encoding.DER)]))
    monkeypatch.setenv("JAVA_HOME", str(home))
    findings = ts.scan_java_cacerts(iocs)
    assert any(f.source == "java-cacerts" and f.type == "compromised_ca_cert"
               for f in findings)


# --------------------------------------------------------------------------- #
# NSS cert9.db source
# --------------------------------------------------------------------------- #

def test_read_nss_db_extracts_cert(tmp_path):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    db = tmp_path / "cert9.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE nssPublic (id INTEGER, a11 BLOB)")
    con.execute("INSERT INTO nssPublic VALUES (1, ?)", (bad.public_bytes(Encoding.DER),))
    con.commit()
    con.close()
    ders = ts._read_nss_db(db)
    assert bad.public_bytes(Encoding.DER) in ders
    # and it feeds a finding
    f = ts.match_cert(ders[0], x509.load_der_x509_certificate(ders[0]), iocs, "nss", str(db))
    assert f and f[0].type == "compromised_ca_cert"


# --------------------------------------------------------------------------- #
# container / rootfs mode
# --------------------------------------------------------------------------- #

def test_scan_rootfs_dirs_and_cacerts(tmp_path):
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    root = tmp_path / "rootfs"
    (root / "etc" / "ssl" / "certs").mkdir(parents=True)
    (root / "etc" / "ssl" / "certs" / "bad.pem").write_bytes(pem_bytes(bad))
    (root / "opt" / "jdk" / "lib" / "security").mkdir(parents=True)
    (root / "opt" / "jdk" / "lib" / "security" / "cacerts").write_bytes(
        _make_jks([bad.public_bytes(Encoding.DER)]))
    findings = ts.dedupe(ts.scan_rootfs(root, iocs))
    sources = {f.source for f in findings}
    assert "rootfs" in sources and "rootfs-java" in sources


def test_scan_rootfs_android_hashed_certs(tmp_path):
    """Android stores each trusted cert as a hash-named file (a1b2c3d4.0) with no
    cert extension; the rootfs scan must still pick it up."""
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    root = tmp_path / "android"
    cacerts = root / "system" / "etc" / "security" / "cacerts"
    cacerts.mkdir(parents=True)
    (cacerts / "a1b2c3d4.0").write_bytes(pem_bytes(bad))   # hash-named, no .pem
    findings = ts.dedupe(ts.scan_rootfs(root, iocs))
    assert any(f.type == "compromised_ca_cert" for f in findings)


def test_scan_containers(tmp_path, monkeypatch):
    """scan_containers walks container layer dirs and scans each layer's cert
    paths; a bad bundle in a layer's etc/ssl/certs is found with source=container."""
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    layer = tmp_path / "overlay2" / "deadbeef" / "diff"
    (layer / "etc" / "ssl" / "certs").mkdir(parents=True)
    (layer / "etc" / "ssl" / "certs" / "ca-certificates.crt").write_bytes(pem_bytes(bad))
    monkeypatch.setattr(ts, "_CONTAINER_LAYER_GLOBS",
                        (str(tmp_path / "overlay2" / "*" / "diff"),))
    findings = ts.dedupe(ts.scan_containers(iocs))
    assert len(findings) == 1
    assert findings[0].source == "container"
    assert findings[0].type == "compromised_ca_cert"
    assert "deadbeef" in findings[0].location   # layer id preserved for mapping


def test_scan_containers_bundle_files_only(tmp_path, monkeypatch):
    """Container scan reads the aggregate bundle file, not a per-cert dir walk:
    an individual non-aggregate cert in the layer's certs dir is NOT reported
    (it isn't the effective trust store), the aggregate IS."""
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    certs = tmp_path / "overlay2" / "cafe01" / "diff" / "etc" / "ssl" / "certs"
    certs.mkdir(parents=True)
    monkeypatch.setattr(ts, "_CONTAINER_LAYER_GLOBS",
                        (str(tmp_path / "overlay2" / "*" / "diff"),))
    (certs / "random-ca.pem").write_bytes(pem_bytes(bad))        # individual -> ignored
    assert ts.scan_containers(iocs) == []
    (certs / "ca-certificates.crt").write_bytes(pem_bytes(bad))  # aggregate -> found
    assert len(ts.dedupe(ts.scan_containers(iocs))) == 1


@pytest.mark.skipif(sys.platform.startswith("win"),
                    reason="symlink creation needs privilege on Windows")
def test_scan_containers_skips_symlink_escaping_layer(tmp_path, monkeypatch):
    """An absolute symlink inside a layer pointing onto the host fs is not followed,
    so we never read a host file and mislabel it as the container's."""
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    hostfile = tmp_path / "host_ca.pem"
    hostfile.write_bytes(pem_bytes(bad))                         # outside any layer
    certs = tmp_path / "overlay2" / "beef02" / "diff" / "etc" / "ssl" / "certs"
    certs.mkdir(parents=True)
    (certs / "ca-certificates.crt").symlink_to(hostfile)        # escapes the layer
    monkeypatch.setattr(ts, "_CONTAINER_LAYER_GLOBS",
                        (str(tmp_path / "overlay2" / "*" / "diff"),))
    assert ts.scan_containers(iocs) == []


@pytest.mark.skipif(not SHIPPED_IOC.exists(), reason="emsign_iocs.json not built")
def test_real_ioc_has_expected_shape():
    data = json.loads(SHIPPED_IOC.read_text(encoding="utf-8"))
    assert len(data["compromised_spki_sha256"]) == 8        # 8 distinct weak keys
    assert len(data["compromised_certs"]) == 16             # x2 issuers each
    scalars = {c["recovered_scalar"] for c in data["compromised_certs"]}
    assert scalars == {4, 56, 66, 115, 155, 156, 230, 237}
    actions = {r["name"]: r["action"] for r in data["affected_roots"]}
    assert actions["AAA Certificate Services"] == "legitimate_root_context"
    assert actions["emSign ECC Root CA - G3"] == "review_distrust"


# --------------------------------------------------------------------------- #
# broadened bundle + app-truststore coverage
# --------------------------------------------------------------------------- #

def test_known_bundle_registry_certs_d(tmp_path, monkeypatch):
    """A compromised root in a container-registry trust dir
    (/etc/docker/certs.d/<registry>/ca.crt) is found via the bundles source."""
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    reg = tmp_path / "certs.d" / "registry.example.com"   # no ':' (invalid on Windows)
    reg.mkdir(parents=True)
    (reg / "ca.crt").write_bytes(pem_bytes(bad))
    monkeypatch.setattr(ts, "_KNOWN_BUNDLE_GLOBS", (str(tmp_path / "certs.d" / "*/"),))
    findings = ts.dedupe(ts.scan_known_bundles(iocs))
    assert any(f.type == "compromised_ca_cert" and f.source == "bundle" for f in findings)


def test_app_truststore_scanned(tmp_path, monkeypatch):
    """A compromised root in an app-server truststore is found via the opt-in
    apptrust source, tagged source=app-truststore."""
    bad, iocs = _bad_cert_and_ioc(tmp_path)
    store_dir = tmp_path / "wildfly" / "standalone" / "configuration"
    store_dir.mkdir(parents=True)
    (store_dir / "application.truststore.pem").write_bytes(pem_bytes(bad))  # PEM: no JKS build
    monkeypatch.setattr(ts, "_APP_TRUSTSTORE_GLOBS", (str(store_dir / "*.pem"),))
    findings = ts.dedupe(ts.scan_app_truststores(iocs))
    assert len(findings) == 1
    assert findings[0].source == "app-truststore"
    assert findings[0].type == "compromised_ca_cert"


def test_default_all_excludes_optin_sources(tmp_path, monkeypatch):
    """The default 'all' source set includes the standard scanners and excludes
    the opt-in ones (containers, apptrust)."""
    captured = {}
    monkeypatch.setattr(ts, "run_scan",
                        lambda paths, iocs, sources, rootfs=(): captured.update(s=set(sources)) or [])
    ioc = tmp_path / "ioc.json"
    ioc.write_text(json.dumps({
        "generated": "2026-10-21",
        "compromised_certs": [{"name": "x", "cert_sha256": "00" * 32, "spki_sha256": "11" * 32}],
        "compromised_spki_sha256": ["11" * 32],
        "compromised_subject_key_identifiers": [], "affected_roots": []}), encoding="utf-8")
    ts.main(["--ioc-file", str(ioc)])          # no --source => default 'all'
    assert {"os", "certifi", "bundles", "env", "java", "nss"} <= captured["s"]
    assert "containers" not in captured["s"]
    assert "apptrust" not in captured["s"]
