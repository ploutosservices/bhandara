#!/usr/bin/env python3
"""A throwaway CA, the proxy's server certificate and four client identities, for the demo only.

    python demo/make-certs.py DIR

Clients (CN = application@environment): demo@dev, other@dev, demo@production, infra-ops@dev.
Runs once per volume: an existing CA is kept, so a running proxy and the tests agree on it.
The certificates are valid for two days.
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
if os.path.exists(os.path.join(out, "ca.pem")):
    print(f"certificates already in {out}; kept (docker compose down -v makes new ones)")
    sys.exit(0)
now = datetime.datetime.now(datetime.timezone.utc)


def key():
    return ec.generate_private_key(ec.SECP256R1())


def write(name, k, cert):
    with open(os.path.join(out, f"{name}.key"), "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    with open(os.path.join(out, f"{name}.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(os.path.join(out, f"{name}.key"), 0o644)   # demo volume, read by nginx and the tests


def issue(cn, ca_key, ca_name, usage, san=None):
    k = key()
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca_name).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=2))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return k, b.sign(ca_key, hashes.SHA256())


ca_key = key()
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo CA")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(minutes=5))
      .not_valid_after(now + datetime.timedelta(days=2))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .sign(ca_key, hashes.SHA256()))
write("ca", ca_key, ca)
write("server", *issue("nginx", ca_key, ca_name, ExtendedKeyUsageOID.SERVER_AUTH, san="nginx"))
for cn in ("demo@dev", "other@dev", "demo@production", "infra-ops@dev"):
    write(cn, *issue(cn, ca_key, ca_name, ExtendedKeyUsageOID.CLIENT_AUTH))
print(f"certificates written to {out}")
