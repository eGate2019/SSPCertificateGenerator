
import uuid


import asn1tools
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype

import constante as cts
from CreateCertificate import PrivateKey, PublicKey
from ui import UI


class AuthenticationToken(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsToken', univ.Sequence()),
        namedtype.NamedType('signatureAlgorithm', univ.Sequence()),
        namedtype.NamedType('signature', univ.Sequence())
    )


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
        # for typ in self.model.types:
        #     print(typ)

    def generate(self, token_parameter):
        """ Generate a token according to a set of parameters."""
        try:
            # Creation of the token builder
            print(token_parameter['modeles'])
            self.setModel(token_parameter['modeles'])
            self.token_name = token_parameter['Name']
            # Getting of the token public key.
            private_ekey = ec.generate_private_key(ec.BrainpoolP256R1)
            private_ekey_der = private_ekey.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                )
            with open("private_keys/" + self.token_name+"-private-key.der", "wb") as f:
                f.write(private_ekey_der)

            public_ekey = private_ekey.public_key()
            public_key_der = public_ekey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_data = self.model.decode(
                'SubjectPublicKeyInfo', public_key_der)
            cert = x509.CertificateBuilder()
            cert = cert.public_key(public_ekey)
            # Collection of the subjet attributes
            for k, m_field in token_parameter.items():

                if k == "issuer":
                    # Get the issuer private key.
                    self.issuer_private_key = PrivateKey(m_field).get()
                    self.issuer_public_key = PublicKey(m_field).get()

            atbsToken = {'version': 0}
            atbsToken['signature'] = {}
            atbsToken['signature']['algorithm'] = cts.OID_ECDSASHA256
            atbsToken['subjectPublicKeyInfo'] = public_key_data
            aRand = uuid.uuid4()
            atbsToken['aATK-Content'] = {
                'aChallenge': aRand.bytes}
            atbsToken['aATK-Content']['aKey-Size'] = cts.KEY_SIZE_E128  # 'Key-Size e128'
            atbsToken['aATK-Content']['aStreamCipherIdentifier'] = cts.AES_CGM  # 'aAES-CGM-StreamCipherIdentifier'

            m_AKI = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.issuer_public_key)
            atbsToken['extensions'] = [{}]
            atbsToken['extensions'][0]['extnID'] = cts.OID_AKI
            atbsToken['extensions'][0]['critical'] = True
            atbsToken['extensions'][0]['extnValue'] = m_AKI.key_identifier

            tbsToken = self.model.encode('TBSToken', atbsToken)
            signature_der = self.issuer_private_key.sign(
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
            self.verify(token_parameter)  
        except ValueError as e:
            print("Oops!..", e)

    def verify(self, token_parameter):
        """ Generate a token according to a set of parameters."""
        try:
            # Creation of the token builder
            self.setModel(token_parameter['modeles'])
            self.token_name = token_parameter['Name']
            for k, m_field in token_parameter.items():

                if k == "issuer":
                    # Get the issuer private key.
                    self.issuer_public_key = PublicKey(m_field).get()         
            subjectKeyIdentifier = x509.SubjectKeyIdentifier.from_public_key(self.issuer_public_key)
            auth_token_der = 0
            # Write our token out to disk.
            with open("./tokens/"+self.path+"_" +
                      self.token_name+".der", "rb") as f:
                auth_token_der = f.read()
            token_verif = self.model.decode('AuthenticationToken',
                                            auth_token_der
                                            )
            if token_verif['tbsToken']['version'] != cts.V1:
                raise Exception("wrong Version")

            if token_verif['tbsToken']['signature']['algorithm'] != cts.OID_ECDSASHA256:
                raise Exception("wrong Signature algorithm")         

            if token_verif['tbsToken']['aATK-Content']['aStreamCipherIdentifier'] not in [cts.AES_CGM]:
                raise Exception("wrong stream cipher identifier")

            if token_verif['tbsToken']['aATK-Content']['aKey-Size'] not in [cts.KEY_SIZE_E128, cts.KEY_SIZE_E256]:
                raise Exception("wrong Key size")

            m_AKI = b'x00'
            for extension in token_verif['tbsToken']['extensions']:
                if extension['extnID'] == cts.OID_AKI:
                    m_AKI = extension['extnValue']

            if subjectKeyIdentifier.digest != m_AKI:
                raise Exception("wrong AKI")

            value = decoder.decode(
                auth_token_der, asn1Spec=AuthenticationToken()
            )
            self.issuer_public_key.verify(
                encoder.encode(value[0].getComponentByPosition(2)),
                encoder.encode(value[0].getComponentByPosition(0)),
                ec.ECDSA(hashes.SHA256()))
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
