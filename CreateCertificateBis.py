import datetime
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import io


class PublicKey:

    def __init__(self, name):
        pu_name = "public_keys/"+name+"-public-key.der"
        with io.open(pu_name, 'rb') as f:
            buf = f.read()
            f.close()
            self.public_key = serialization.load_der_public_key(
                buf, backend=default_backend()
            )

    def get(self):
        return self.public_key


class PrivateKey:

    def __init__(self, name):
        f = open("private_keys/"+name+"-private-key.der", "rb")
        buf = f.read()
        f.close()
        self.private_key = serialization.load_der_private_key(
            buf, password=None,
            backend=default_backend()
        )

    def get(self):
        return self.private_key


class SSPcertificate:

    def __init__(self):
        pass

    def generate(self, certificate_parameter):
        # Generate a private key for use in the exchange.
        try:
            cert = x509.CertificateBuilder()
            self.cert_name = certificate_parameter['Name']
            public_key = PublicKey(self.cert_name)

            attribute_subject = []
            for k, m_field in certificate_parameter.items():
                print(k, "--->", m_field)

                if k == "issuer":
                    private_key_issuer = PrivateKey(m_field)
                    public_key_issuer = PublicKey(m_field)
                    cert = cert.add_extension(
                        x509.SubjectKeyIdentifier.from_public_key
                        (public_key.get()),
                        critical=False)
                    cert = cert.issuer_name(x509.Name([
                        x509.NameAttribute(
                                NameOID.COMMON_NAME, m_field)
                    ]))
                if k == "subject":
                    for k, v in m_field.items():
                        print(k, "<-->", v)
                        if k == "C":
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.COUNTRY_NAME, v)
                            )
                        if k == "ST":
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.STATE_OR_PROVINCE_NAME, v))
                        if k == "O":
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, v)
                            )
                        if k == "OU":
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.ORGANIZATIONAL_UNIT_NAME, v)
                            )
                        if k == "CN":
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.COMMON_NAME, v)
                            )
                        if k == "L":
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.LOCALITY_NAME, v)
                            )

                if k == "serial_number":
                    cert = cert.serial_number(m_field)
                if k == "not_before":
                    cert = cert.not_valid_before(
                        datetime.datetime.fromisoformat(m_field)
                    )
                if k == "not_after":
                    cert = cert.not_valid_after(
                        datetime.datetime.fromisoformat(m_field)
                    )
                if k == "extensions":
                    for k, v in m_field.items():
                        print(k, "<-->", v)
                        if k == "BasicConstraints":
                            if v["value"]["CA"]:
                                cert = cert.add_extension(
                                    x509.BasicConstraints(
                                        ca=True,
                                        path_length=v["value"]["pathlen"]
                                    ),
                                    critical=v["critical"]
                                )
                            else:
                                cert = cert.add_extension(
                                    x509.BasicConstraints(
                                        ca=False),
                                    critical=v["critical"]
                                )

            subject = x509.Name(attribute_subject)
            cert = cert.subject_name(subject)

            cert = cert.public_key(public_key.get())
            cert = cert.add_extension(x509.KeyUsage(
                True, False, False, False, False, False, False, False, False
                ),
                critical=True
            )
            cert = cert.sign(
                private_key_issuer.get(),
                hashes.SHA256(),
                default_backend()
             )
            # Write our certificate out to disk.
            with open("certificates/"+self.cert_name+".der", "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.DER))

        except ValueError as e:
            print("Oops!..", e)


f = open("ETSI-SSP-CI-param.json", 'r')
buf = f.read()
f.close()
paths = json.loads(buf)
for path in paths:
    records = paths[path]
    print("Cert name: "+records["Name"])
    m_cert = SSPcertificate()
    m_cert.generate(records)
