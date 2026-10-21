#!/usr/bin/env python3
"""Build and VERIFY the emSign/eMudhra IOC file from the community tracker data.

Run in isolated mode because the input JSON is untrusted downloaded data:

    python -I tools/build_iocs.py <impacted-intermediates.json> <roots.json> <out.json>

For every certificate this script:
  * parses the embedded PEM with the vetted `cryptography` library,
  * recomputes the cert SHA-256 (over DER) and the public-key SHA-256 (over the
    SubjectPublicKeyInfo) and asserts they match the values claimed in the
    source JSON -- so a tampered or mistyped download fails closed, and
  * for each compromised intermediate, independently confirms the key is weak
    by recovering its small private scalar.

The result is an IOC file whose fingerprints are self-verified, not merely
copied from a third party.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def norm_hex(value: str) -> str:
    return value.replace(":", "").replace(" ", "").lower()


def canon_serial(serial_int: int) -> str:
    """Canonical serial: lowercase hex, zero-padded to an even (byte) length."""
    h = format(serial_int, "x")
    return ("0" + h) if len(h) % 2 else h


def cert_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def spki_sha256(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def recover_small_scalar(cert: x509.Certificate, max_scalar: int = 1024):
    """Return small d with d*G == the cert's EC public point, else None."""
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return None
    curve = pub.curve
    target = pub.public_numbers()
    for d in range(1, max_scalar + 1):
        nums = ec.derive_private_key(d, curve).public_key().public_numbers()
        if nums.x == target.x and nums.y == target.y:
            return d
    return None


def verify_entry(entry: dict) -> x509.Certificate:
    """Parse PEM and assert its recomputed fingerprints match the source JSON."""
    cert = x509.load_pem_x509_certificate(entry["pem"].encode())
    got_cert = cert_sha256(cert)
    got_spki = spki_sha256(cert)
    want_cert = norm_hex(entry["sha256"])
    want_spki = norm_hex(entry["spki_sha256"])
    if got_cert != want_cert:
        raise SystemExit(
            f"FAIL cert sha256 mismatch for {entry['name']!r}: "
            f"computed {got_cert} != claimed {want_cert}"
        )
    if got_spki != want_spki:
        raise SystemExit(
            f"FAIL spki sha256 mismatch for {entry['name']!r}: "
            f"computed {got_spki} != claimed {want_spki}"
        )
    # Cross-check the serial by integer value (source JSON may zero-pad).
    want_serial = int(norm_hex(entry["serial_hex"]), 16)
    if cert.serial_number != want_serial:
        raise SystemExit(
            f"FAIL serial mismatch for {entry['name']!r}: "
            f"{canon_serial(cert.serial_number)} != {norm_hex(entry['serial_hex'])}"
        )
    return cert


def ski_hex(cert: x509.Certificate):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ext.value.digest.hex()
    except x509.ExtensionNotFound:
        return None


def root_action(name: str, operator: str) -> str:
    """Only the emSign roots are to be distrusted; AAA is a legitimate root."""
    if name.startswith("emSign"):
        return "review_distrust"
    return "legitimate_root_context"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    inter_path, roots_path, out_path = (Path(p) for p in argv)

    intermediates = json.loads(inter_path.read_text(encoding="utf-8"))
    roots = json.loads(roots_path.read_text(encoding="utf-8"))

    compromised_certs = []
    spki_set: set[str] = set()
    ski_set: set[str] = set()

    for entry in intermediates:
        cert = verify_entry(entry)
        scalar = recover_small_scalar(cert)
        if scalar is None:
            raise SystemExit(
                f"FAIL {entry['name']!r} claimed compromised but no small scalar found"
            )
        ski = ski_hex(cert)
        compromised_certs.append({
            "name": entry["name"],
            "usage": entry.get("usage"),
            "subject": entry["subject"],
            "issuer": entry["issuer"],
            "issued_by": entry.get("issued_by"),
            "issuer_operator": entry.get("issuer_operator"),
            "serial_hex": canon_serial(cert.serial_number),
            "cert_sha256": cert_sha256(cert),
            "spki_sha256": spki_sha256(cert),
            "subject_key_identifier": (ski or norm_hex(entry.get("subject_key_identifier", ""))),
            "recovered_scalar": scalar,
            "curve": entry.get("key", {}).get("curve"),
            "revocation_reason": entry.get("revocation", {}).get("reason"),
            "revocation_date": entry.get("revocation", {}).get("date"),
        })
        spki_set.add(spki_sha256(cert))
        if ski:
            ski_set.add(ski)

    affected_roots = []
    for entry in roots:
        cert = verify_entry(entry)
        affected_roots.append({
            "name": entry["name"],
            "operator": entry.get("operator"),
            "role": entry.get("role"),
            "subject": entry["subject"],
            "serial_hex": canon_serial(cert.serial_number),
            "cert_sha256": cert_sha256(cert),
            "spki_sha256": spki_sha256(cert),
            "subject_key_identifier": (ski_hex(cert) or ""),
            "root_store_status": entry.get("root_store_status"),
            "action": root_action(entry["name"], entry.get("operator", "")),
        })

    out = {
        "schema": "emsign-ioc/1",
        "generated": datetime.date.today().isoformat(),
        "incident": "eMudhra/emSign intermediate CA private key compromise (Oct 2026)",
        "source": "emudhra.we-have-a-problem.com (impacted-intermediates.json, roots.json); "
                  "fingerprints independently recomputed and weak keys reconfirmed by build_iocs.py",
        "compromised_certs": compromised_certs,
        "compromised_spki_sha256": sorted(spki_set),
        "compromised_subject_key_identifiers": sorted(ski_set),
        "affected_roots": affected_roots,
    }
    out_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"OK: verified {len(compromised_certs)} compromised cert entries "
          f"({len(spki_set)} distinct weak keys), {len(affected_roots)} roots "
          f"-> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
