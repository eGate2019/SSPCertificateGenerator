import datetime
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


class PublicKey:
    def __init__(self, name):

        f = open("public_keys/"+name+"-public-key.pem")
        buf = f.read()
        f.close()
        self.public_key = serialization.load_pem_public_key(
            buf,
            backend=default_backend()
        )

    def get(self):
        return self.public_key


class PrivateKey:

    def __init__(self, name):
        f = open("private_keys/"+name+"-private-key.pem")
        buf = f.read()
        f.close()
        self.private_key = serialization.load_pem_private_key(
            buf,
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
                    private_key_issuer = PublicKey(m_field)

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
                    cert = cert.not_valid_before(datetime.fromisoformat(
                        m_field)
                    )
                if k == "not_after":
                    cert = cert.not_valid_after(datetime.fromisoformat(
                        m_field)
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
            cert = cert.public_key(public_key)
            cert = cert.add_extension(x509.KeyUsage(
                True, False, False, False, False, False, False, False, False
                ),
                critical=True
            )
            cert = cert.sign(
                private_key_issuer,
                hashes.SHA256(),
                default_backend()
             )
            # Write our certificate out to disk.
            with open("certificates/"+self.cert_name+".pem", "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        except ValueError as e:
            print("Oops!..", e)


with open("ETSI-SSP-CI-param.yaml", 'r') as f:
    paths = yaml.load_all(f, Loader=yaml.FullLoader)
    for path in paths:
        for k, v in path.items():
            print(k, ":->", v)
            print("Cert name: "+v["Name"])
            m_cert = SSPcertificate()
            m_cert.generate(v)
