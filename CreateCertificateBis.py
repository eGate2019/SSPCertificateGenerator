from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import datetime
from cryptography.hazmat.primitives.serialization import Encoding

# Generate a private key for use in the exchange.
try:
    private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend())

    public_key = private_key.public_key()

    subject= x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"RD"),
        x509.NameAttribute(NameOID.SURNAME, u"AR")         
    ])

    issuer= x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"RD"),
        x509.NameAttribute(NameOID.SURNAME, u"AR")         
    ])
    cert = x509.CertificateBuilder()
    cert=cert.subject_name(subject)
    cert=cert.issuer_name(issuer)
    cert=cert.public_key(public_key)
    cert=cert.serial_number(x509.random_serial_number())
    cert=cert.not_valid_before(datetime.datetime.utcnow())
    cert=cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
    cert=cert.add_extension(x509.SubjectAlternativeName(
        [x509.DNSName(u"localhost")]),
        critical=False)
    cert=cert.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)     
    cert=cert.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    cert=cert.sign(private_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(encoding=Encoding.PEM))

except ValueError as e:
    print("Oops!..", e)
