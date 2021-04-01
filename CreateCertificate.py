import yaml
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import io
from ui import UI
import constante as cts


class PublicKey:
    """Base class for a handling a public key."""

    def __init__(self, name):
        """Instantiate the object."""
        pu_name = cts.PATH_PUBLIC + name + "-public-key.der"
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
        f = open(cts.PATH_PRIVATE + name + "-private-key.der", "rb")
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

    def __init__(self):
        """Instantiate the object."""
        pass

    def generate(self, certificate_parameter):
        """ Generate a certificate according to a set of parameters."""
        try:
            # Creation of the certificate builder
            cert = x509.CertificateBuilder()

            # Collection of the subjet attributes
            attribute_subject = []
            attribute_issuer = []
            for k, m_field in certificate_parameter.items():

                if k == cts.KW_ISSUER:
                    # Collect of the issuer attributes
                    for k, v in m_field.items():
                        if k == cts.KW_C:
                            attribute_issuer.append(x509.NameAttribute(
                                NameOID.COUNTRY_NAME, v)
                            )
                        if k == cts.KW_ST:
                            attribute_issuer.append(x509.NameAttribute(
                                NameOID.STATE_OR_PROVINCE_NAME, v))
                        if k == cts.KW_O:
                            attribute_issuer.append(x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, v)
                            )
                        if k == cts.KW_OU:
                            attribute_issuer.append(x509.NameAttribute(
                                NameOID.ORGANIZATIONAL_UNIT_NAME, v)
                            )
                        if k == cts.KW_CN:
                            attribute_issuer.append(x509.NameAttribute(
                                NameOID.COMMON_NAME, v)
                            )
                            # Get the issuer private key.
                            self.issuer_private_key = PrivateKey(v)
                            # Get the issur public key.
                            self.issuer_public_key = PublicKey(v)
                        if k == cts.KW_LN:
                            attribute_issuer.append(x509.NameAttribute(
                                NameOID.LOCALITY_NAME, v)
                            )

                    # Add the Authority Key Identifier (back chaining)
                    cert = cert.add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(
                            self.issuer_public_key.get()), critical=True)

                if k == cts.KW_SUBJECT:
                    # Collect of the subject attribute
                    for k, v in m_field.items():
                        if k == cts.KW_C:
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.COUNTRY_NAME, v)
                            )
                        if k == cts.KW_ST:
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.STATE_OR_PROVINCE_NAME, v))
                        if k == cts.KW_O:
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, v)
                            )
                        if k == cts.KW_OU:
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.ORGANIZATIONAL_UNIT_NAME, v)
                            )
                        if k == cts.KW_CN:
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.COMMON_NAME, v)
                            )
                            print("Certificate generation: ", v)
                            # Getting of the certificate public key.
                            self.public_key = PublicKey(v)
                            self.cert_name = v

                        if k == cts.KW_LN:
                            attribute_subject.append(x509.NameAttribute(
                                NameOID.LOCALITY_NAME, v)
                            )

                    # Add the Subject Key Identifier extension.
                    cert = cert.add_extension(
                        x509.SubjectKeyIdentifier.from_public_key
                        (self.public_key.get()),
                        critical=False)

                if k == cts.KW_SERIAL_NUMBER:
                    # Add the serial number.
                    cert = cert.serial_number(m_field)
                if k == cts.KW_NOT_BEFORE:
                    # Add the low limit validity date.
                    cert = cert.not_valid_before(
                        datetime.datetime.fromisoformat(m_field)
                    )
                if k == cts.KW_NOT_AFTER:
                    # Add the high limit validity date
                    cert = cert.not_valid_after(
                        datetime.datetime.fromisoformat(m_field)
                    )
                if k == cts.KW_EXTENSIONS:
                    # Collect the extensions.
                    for k, v in m_field.items():
                        if k == cts.KW_BASICCONSTRAINTS:
                            # Add the basic constraints extension.
                            if v[cts.KW_VALUE][cts.KW_CA]:
                                cert = cert.add_extension(
                                    x509.BasicConstraints(
                                        ca=True,
                                        path_length=v[cts.KW_VALUE][cts.KW_PATHLEN]
                                    ),
                                    critical=v[cts.KW_CRITICAL]
                                )
                            else:
                                cert = cert.add_extension(
                                    x509.BasicConstraints(
                                        path_length=None,
                                        ca=False),
                                    critical=v[cts.KW_CRITICAL]
                                )
                        if k == cts.KW_CERTIFICATEPOLICIES:
                            # Add the certificate policies extension.
                            cert = cert.add_extension(
                                x509.CertificatePolicies([
                                    x509.PolicyInformation(
                                        x509.ObjectIdentifier(
                                            v[cts.KW_VALUE]
                                            [cts.KW_IDENTIFIER]),
                                        [x509.UserNotice(
                                            explicit_text=v[cts.KW_VALUE]
                                            [cts.KW_EXPLICIT_TEXT],
                                            notice_reference=None
                                            )])
                                ]),
                                critical=v[cts.KW_CRITICAL])
            # Init the issuer name.
            cert = cert.issuer_name(x509.Name(attribute_issuer))
            # Init the subject name.
            cert = cert.subject_name(x509.Name(attribute_subject))
            # Init of the subject public key
            cert = cert.public_key(self.public_key.get())
            # Add the key usage extension
            cert = cert.add_extension(x509.KeyUsage(
                True, False, False, False, False, False, False, False, False
                ),
                critical=True
            )
            # Sign the certificate with the issuer private key.
            cert = cert.sign(
                self.issuer_private_key.get(),
                hashes.SHA256(),
                default_backend()
             )
            # Write our certificate out to disk.
            with open(cts.PATH_CERTIFICATES +
                      self.cert_name+".der", "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.DER))
            with open(cts.PATH_CERTIFICATES +
                      self.cert_name+".pem", "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        except ValueError as e:
            print("Oops!..", e)

# Open the YAML parameter file


CERTCONFIGURATION = {
    'options': 'c:h:i:o',
    'description': ["ifile=", "ofile=", "ccommand="],
    'usage': 'CreateCertificate.py -c <command> [-i <inputfile>] [-o <outputfile>]'
}
if __name__ == "__main__":
    my_ui = UI(CERTCONFIGURATION)
    if my_ui.isInputFile():
        f = open(my_ui.getInputFile(), 'r', encoding='utf-8')
        # Load the YAML file containing the parameters.
        paths = list(yaml.load_all(f, Loader=yaml.FullLoader))
        f.close()
        # print(paths)
        # Scan all certificate parameters.
        for certificate in paths[0]:
            # Instantiate a certificate.
            m_cert = SSPcertificate()
            # # Generate the certificate according to the parameters.
            m_cert.generate(certificate)
