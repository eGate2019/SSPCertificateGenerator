import yaml
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import io
from ui import UI


class PublicKey:
    """Base class for a handling a public key."""

    def __init__(self, name):
        """Instantiate the object."""
        pu_name = "public_keys/"+name+"-public-key.der"
        with io.open(pu_name, 'rb') as f:
            buf = f.read()
            f.close()
            self.public_key = serialization.load_der_public_key(
                buf, backend=default_backend()
            )

    def get(self):
        """Get the native public key."""
        return self.public_key


class PrivateKey:
    """Base class for a handling a public key."""

    def __init__(self, name):
        """Instantiate the object."""
        f = open("private_keys/"+name+"-private-key.der", "rb")
        buf = f.read()
        f.close()
        self.private_key = serialization.load_der_private_key(
            buf, password=None,
            backend=default_backend()
        )

    def get(self):
        """Get the native private key."""
        return self.private_key


class SSPcertificate:
    """Base class for a handling a SSP certificate."""

    def __init__(self, path):
        """Instantiate the object."""
        self.path = path

    def generate(self, certificate_parameter):
        """ Generate a certificate according to a set of parameters."""
        try:
            # Creation of the certificate builder
            cert = x509.CertificateBuilder()
            self.cert_name = certificate_parameter['Name']
            # Getting of the certificate public key.
            public_key = PublicKey(self.cert_name)

            # Collection of the subjet attributes
            attribute_subject = []
            for k, m_field in certificate_parameter.items():

                if k == "issuer":
                    # Get the issuer private key.
                    issuer_private_key = PrivateKey(m_field)
                    # Get the issur public key.
                    issuer_public_key = PublicKey(m_field)
                    # Add the Subject Key Identifier extension.
                    cert = cert.add_extension(
                        x509.SubjectKeyIdentifier.from_public_key
                        (public_key.get()),
                        critical=False)
                    # Add the issuer common name.
                    cert = cert.issuer_name(x509.Name([
                        x509.NameAttribute(
                                NameOID.COMMON_NAME, m_field)
                    ]))
                    # Add the Authority Key Identifier (back chaining)
                    cert = cert.add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(
                            issuer_public_key.get()), critical=True)

                if k == "subject":
                    # Collect of the subject attribute
                    for k, v in m_field.items():
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
                    # Add the serial number.
                    cert = cert.serial_number(m_field)
                if k == "not_before":
                    # Add the low limit validity date.
                    cert = cert.not_valid_before(
                        datetime.datetime.fromisoformat(m_field)
                    )
                if k == "not_after":
                    # Add the high limit validity date
                    cert = cert.not_valid_after(
                        datetime.datetime.fromisoformat(m_field)
                    )
                if k == "extensions":
                    # Collect the extensions.
                    for k, v in m_field.items():
                        if k == "BasicConstraints":
                            # Add the basic constraints extension.
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
                        if k == "CertificatePolicies":
                            # Add the certificate policies extension.
                            cert = cert.add_extension(
                                x509.CertificatePolicies([
                                    x509.PolicyInformation(
                                        x509.ObjectIdentifier(
                                            v["value"]
                                            ["identifier"]),
                                        [x509.UserNotice(
                                            explicit_text=v["value"]
                                            ["explicit_text"],
                                            notice_reference=None
                                            )])
                                ]),
                                critical=v["critical"])
            # Init the subject name.
            cert = cert.subject_name(x509.Name(attribute_subject))
            # Init of the subject public key
            cert = cert.public_key(public_key.get())
            # Add the key usage extension
            cert = cert.add_extension(x509.KeyUsage(
                True, False, False, False, False, False, False, False, False
                ),
                critical=True
            )
            # Sign the certificate with the issuer private key.
            cert = cert.sign(
                issuer_private_key.get(),
                hashes.SHA256(),
                default_backend()
             )
            # Write our certificate out to disk.
            with open("./certificates/"+self.path+"_" +
                      self.cert_name+".der", "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.DER))
            with open("./certificates/" +
                      self.path+"_"+self.cert_name+".pem", "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        except ValueError as e:
            print("Oops!..", e)

# Open the YAML parameter file


if __name__ == "__main__":
    my_ui = UI()
    if my_ui.isInputFile():
        f = open(my_ui.getInputFile(), 'r', encoding='utf-8')
        # Load the YAML file containing the parameters.
        paths = list(yaml.load_all(f, Loader=yaml.FullLoader))
        f.close()
        # print(paths)
        # Scan all certificate parameters.
        for path in paths:
            # print("Certification path:", path)
            for element in path:
                print(element)
                for certificate in element:
                    m_certificate = list(certificate)
                    print("Certificate generation: ", m_certificate["Name"])
                    # Instantiate a certificate.
                    # m_cert = SSPcertificate(element)
                    # # Generate the certificate according to the parameters.
                    # m_cert.generate(records)
