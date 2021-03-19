import datetime
import uuid

import asn1tools
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import constante as cts
from CreateCertificate import PrivateKey, PublicKey
from ui import UI


class RawKey:
    """Base class for a handling a public key."""

    def __init__(self, name):
        """Instantiate the object."""
        f = open("public_keys/"+name+"-public-key.der", "rb")
        self.public_key = f.read()
        f.close()

    def get(self):
        """Get the native public key."""
        return self.public_key


class SSPtoken:
    """Base class for a handling a SSP token."""

    def __init__(self, path):
        """Instantiate the object."""
        self.path = path

    def setModel(self, modeles):
        """Set the ASN.1 model."""
        self.model = asn1tools.compile_files(modeles, 'der')
        for typ in self.model.types:
            print(typ)

    def generate(self, token_parameter):
        """ Generate a token according to a set of parameters."""
        try:
            # Creation of the token builder
            print(token_parameter['modeles'])
            self.setModel(token_parameter['modeles'])
            self.token_name = token_parameter['Name']
            # Getting of the token public key.
            private_key = ec.generate_private_key(ec.BrainpoolP256R1)
            public_key = private_key.public_key()
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_data= self.model.decode('SubjectPublicKeyInfo', public_key_der)
            cert = x509.CertificateBuilder()
            cert = cert.public_key(public_key)
            # Collection of the subjet attributes
            for k, m_field in token_parameter.items():

                if k == "issuer":
                    # Get the issuer private key.
                    self.issuer_private_key = PrivateKey(m_field),
                    self.issuer_public_key = PublicKey(m_field)

            atbsToken = {'version': 0}
            atbsToken['subjectPublicKeyInfo'] = public_key_data
            aRand = uuid.uuid4()
            atbsToken['aATK-Content'] = {
                'aChallenge': aRand.bytes}
            atbsToken['aATK-Content']['aKey-Size'] = cts.KEY_SIZE_E128  # 'Key-Size e128'
            atbsToken['aATK-Content']['aStreamCipherIdentifier'] = cts.AES_CGM  # 'aAES-CGM-StreamCipherIdentifier'
            tbsToken = self.model.encode('TBSToken', atbsToken)
            signature_der = private_key.sign(
                tbsToken, ec.ECDSA(hashes.SHA256()))
            signature_data = self.model.decode(
                'ECDSA-Sig-Value', signature_der)
            auth_token = {}
            auth_token['tbsToken'] = atbsToken
            auth_token['signature'] = signature_data
            auth_token['signatureAlgorithm'] = {}
            auth_token['signatureAlgorithm']['algorithm'] = cts.OID_ECDSASHA256
            auth_token_der = self.model.encode(
                'AuthenticationToken', auth_token)
            # Write our token out to disk.
            with open("./tokens/"+self.path+"_" +
                      self.token_name+".der", "wb") as f:
                f.write(auth_token_der)

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
        # Scan all token parameters.
        for path in paths:
            # print("Certification path:", path)
            for m_token in path:
                print("token generation: ", m_token['Name'])
                # Instantiate a token.
                m_cert = SSPtoken("")
                # # Generate the token according to the parameters.
                m_cert.generate(m_token)
