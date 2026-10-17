#!/usr/bin/env python3
"""
Generate self-signed TLS certificates for InsiEDR Nginx reverse proxy.
Usage: python scripts/generate_certs.py [domain]
"""
import datetime
import ipaddress
import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(output_dir: Path, domain: str = "localhost"):
    output_dir.mkdir(parents=True, exist_ok=True)
    key_path = output_dir / "server.key"
    cert_path = output_dir / "server.crt"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InsiEDR EDR Platform"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    san_list = [
        x509.DNSName(domain),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated TLS certificate and key in {output_dir}")
    print(f" - Certificate: {cert_path}")
    print(f" - Private Key: {key_path}")


if __name__ == "__main__":
    target_domain = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    cert_dir = Path(__file__).resolve().parent.parent / "nginx" / "certs"
    generate_self_signed_cert(cert_dir, domain=target_domain)
