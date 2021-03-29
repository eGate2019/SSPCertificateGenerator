
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


class Certificate(univ.Sequence):
    pass


class CertificationPath(univ.SetOf):
    """Base class for a certificate lists."""
    pass


class AuthenticationToken(univ.Sequence):
    """Base class for an authentication token."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsToken', univ.Sequence()),
        namedtype.NamedType('signatureAlgorithm', univ.Sequence()),
        namedtype.NamedType('signature', univ.Sequence())
    )


class AuthenticationTokenCredential(univ.Sequence):
    """Base class for an authentication token."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('token', univ.Sequence()),
        namedtype.NamedType(cts.KW_PATH, univ.SetOf())
        )


class SSPtoken:
    """Base class for a handling a SSP token."""

    def __init__(self, path):
        """Instantiate the object."""
        self.path = path

    def setModel(self, modeles):
        """Set the ASN.1 model."""
        self.model = asn1tools.compile_files(modeles, 'der')
 
    def generateChallenge(self, parameters):
        file_name = cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] + ".bin"
        if parameters[cts.KW_GENERATE]:
            # Generate a challenge as a random
            aRand = uuid.uuid4()
            self.m_challenge = aRand.bytes
            # Save the private key for additional operations.
            with open(file_name, "wb") as f:
                f.write(self.m_challenge)
        else:
            with open(file_name, "rb") as f:
                self.m_challenge = f.read()

    def generatePath(self, parameters):
        """ Generate the certification path."""
        # Load the models
        self.setModel(parameters[cts.KW_MODELES])
        # Instantiate the CertificationPath
        self.path = CertificationPath()
        # Load the certificates according to the configuration file
        position = 0
        for certificate in parameters[cts.KW_PATH]:
            # Load the certificate from the disk.
            filename = cts.PATH_CERTIFICATES + certificate+".der"
            with open(filename, "rb") as f:
                certificate_der = f.read()
                value = decoder.decode(certificate_der,
                                       asn1Spec=Certificate())
                self.path.setComponentByPosition(position, value[0])
                position = position + 1
        # If Name of the certification path is present then the data are 
        # serialized and saved on a file
        if cts.KW_NAME in parameters:
            certificationPath_der = encoder.encode(self.path)
            with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                      ".der", "wb") as f:
                f.write(certificationPath_der)

    def generateCredentials(self, parameters):
        """ Generate the Authentication credentials for the AAS-OP-AUTHENTICATE-Command."""
        self.atk = AuthenticationTokenCredential()
        # Load the authentication token previously computed
        self.atk.setComponentByName('token', value=self.authenticationToken[0])
        # Load the certification path previously computed
        self.atk.setComponentByName(cts.KW_PATH, value=self.path)
        if cts.KW_NAME in parameters:
            # Serialize the authentication token
            authenticationTokenCredential_der = encoder.encode(self.atk)
            with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                    ".der", "wb") as f:
                f.write(authenticationTokenCredential_der)

    def generateToken(self, parameters):
        """ Generate a token according to a set of parameters."""
        try:
            # Creation of the token builder
            print(parameters[cts.KW_MODELES])
            self.setModel(parameters[cts.KW_MODELES])
            self.token_name = parameters[cts.KW_NAME]
            # Generate a pair of private/public keys for EDCDH operations.
            if parameters[cts.KW_ECKA_CURVE] not in cts.CURVES:
                raise Exception("wrong ECC curve")
            private_ekey = ec.generate_private_key(
                cts.CURVES[parameters[cts.KW_ECKA_CURVE]])
            # Serialize the private key to a DER format
            private_ekey_der = private_ekey.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                )
            # Save the private key for additional operations.
            with open(cts.PATH_PRIVATE + self.token_name +
                      "-private-key.der", "wb") as f:
                f.write(private_ekey_der)
            # Compute the public key from the private key.
            public_ekey = private_ekey.public_key()
            # Encode the public key according to the DER format.
            public_key_der = public_ekey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Create a public key info.
            public_key_data = self.model.decode(
                'SubjectPublicKeyInfo', public_key_der)

            # Collection of the subjet attributes
            for k, m_field in parameters.items():

                if k == cts.KW_ISSUER:
                    # Get the issuer private key.
                    self.issuer_private_key = PrivateKey(m_field).get()
                    self.issuer_public_key = PublicKey(m_field).get()

            # Create the structure for generating the authentication token body
            atbsToken = {'version': cts.V1}
            # Fill the signature parameters
            atbsToken['signature'] = {}
            atbsToken['signature']['algorithm'] = cts.OID_ECDSASHA256
            atbsToken['subjectPublicKeyInfo'] = public_key_data

            # Fill the ATK-Content
            atbsToken['aATK-Content'] = {
                'aChallenge': self.m_challenge}
            if parameters[cts.KW_KEYSIZE] not in cts.KEY_SIZES:
                raise Exception("wrong Key size")
                        # fill the challenge field
            atbsToken['aATK-Content']['aKey-Size'] = cts.KEY_SIZES[parameters[cts.KW_KEYSIZE]]  # 'Key-Size 128 or 256'
            atbsToken['aATK-Content']['aStreamCipherIdentifier'] = cts.AES_CGM  # 'aAES-CGM-StreamCipherIdentifier'
            # Create the AKI structure
            m_AKI = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.issuer_public_key)
            # Fill the AKI extension
            atbsToken['extensions'] = [{}]
            atbsToken['extensions'][0]['extnID'] = cts.OID_AKI
            atbsToken['extensions'][0]['critical'] = True
            atbsToken['extensions'][0]['extnValue'] = m_AKI.key_identifier
            # Encode the TBSToken
            tbsToken = self.model.encode('TBSToken', atbsToken)

            # Generate the signature
            signature_der = self.issuer_private_key.sign(
                tbsToken, ec.ECDSA(hashes.SHA256()))
            # Convert the DER format to a dictionary
            signature_data = self.model.decode(
                'ECDSA-Sig-Value', signature_der)

            # Create the authentication token structure
            auth_token = {}
            # Fill the authentication token body
            auth_token['tbsToken'] = atbsToken
            # Fill the authentication token signature
            auth_token['signature'] = signature_data
            auth_token['signatureAlgorithm'] = {}
            auth_token['signatureAlgorithm']['algorithm'] = cts.OID_ECDSASHA256
            # Encode the authentication token using the DER formaty
            auth_token_der = self.model.encode(
                cts.KW_AUTHENTICATIONTOKEN, auth_token)
            # Save the authentication token on to disk.
            with open(cts.PATH_TOKENS +
                      self.token_name+".der", "wb") as f:
                f.write(auth_token_der)
            # Verify the authentication token
            self.verifyToken(parameters)

        except ValueError as e:
            # Catch an execption if it is occured
            print("Oops!..", e)

    def verifyToken(self, parameters):
        """ Generate a token according to a set of parameters."""
        try:
            # Creation of the token builder
            self.setModel(parameters[cts.KW_MODELES])
            self.token_name = parameters[cts.KW_NAME]
            for k, m_field in parameters.items():

                if k == "issuer":
                    # Get the issuer public key.
                    self.issuer_public_key = PublicKey(m_field).get()         
            # Create a subject key identifier from the issuer public key
            authorityKeyIdentifier = x509.SubjectKeyIdentifier.from_public_key(self.issuer_public_key)
            auth_token_der = 0
            # Load the authentication token from the disk.
            with open(cts.PATH_TOKENS +
                      self.token_name+".der", "rb") as f:
                auth_token_der = f.read()

            # Decode the authentication token DER data
            token_verif = self.model.decode(cts.KW_AUTHENTICATIONTOKEN,
                                            auth_token_der
                                            )
            # Check if the version is right
            if token_verif['tbsToken']['version'] != cts.V1:
                raise Exception("wrong Version")
            # Check if the signature algorithm identifier is right before
            # verifying the signature
            if token_verif['tbsToken']['signature']['algorithm'] != cts.OID_ECDSASHA256:
                raise Exception("wrong Signature algorithm")
            # Check if the signature streamcipher algorithm identifier is right
            if token_verif['tbsToken']['aATK-Content']['aStreamCipherIdentifier'] not in [cts.AES_CGM]:
                raise Exception("wrong stream cipher identifier")
            # Check if the key sizz is known
            if token_verif['tbsToken']['aATK-Content']['aKey-Size'] not in [cts.KEY_SIZE_E128, cts.KEY_SIZE_E256]:
                raise Exception("wrong Key size")
            # Scan the extensions
            m_AKI = b'x00'
            for extension in token_verif['tbsToken']['extensions']:
                # Check if the extension is AKI
                if extension['extnID'] == cts.OID_AKI:
                    # Intermediate saving of the AKI
                    m_AKI = extension['extnValue']
            # Check if Authority Key Identifier (AKI) is right
            if authorityKeyIdentifier.digest != m_AKI:
                raise Exception("wrong AKI")
            # Check if the authentication is well-formed
            self.authenticationToken = decoder.decode(
                auth_token_der, asn1Spec=AuthenticationToken()
            )
            # Verify the signature
            self.issuer_public_key.verify(
                encoder.encode(self.authenticationToken[0].getComponentByPosition(2)),
                encoder.encode(self.authenticationToken[0].getComponentByPosition(0)),
                ec.ECDSA(hashes.SHA256()))
        except ValueError as e:
            print("Oops!..", e)

# Open the YAML parameter file


tokenConfiguration = {
    'options': ':c:hi:o',
    'description': ["ifile=", "ofile=", "ccommand="],
    'usage': 'CreateToken.py [-c <command>] [-i <inputfile>] [-o <outputfile>]'
}
if __name__ == "__main__":
    try:
        my_ui = UI(tokenConfiguration)
        if my_ui.isInputFile():
            f = open(my_ui.getInputFile(), 'r', encoding='utf-8')
            # Load the YAML file containing the parameters.
            paths = list(yaml.load_all(f, Loader=yaml.FullLoader))
            f.close()
            # print(paths)
            # Scan all token parameters.
            m_cert = SSPtoken("")
            for path in paths:
                for m_token in path:
                    parameters = path[m_token]
                    if m_token == cts.KW_CHALLENGE:
                        m_cert.generateChallenge(parameters)

                    if m_token == cts.KW_CERTIFICATIONPATH:
                        m_cert.generatePath(parameters)

                    if m_token == cts.KW_AUTHENTICATIONTOKENCREDENTIALS:
                        m_cert.generateCredentials(parameters)

                    if m_token == cts.KW_AUTHENTICATIONTOKEN:
                        print("token generation: ", parameters[cts.KW_NAME])
                        # Instantiate a token.
                        # # Generate the token according to the parameters.
                        m_cert.generateToken(parameters)

    except ValueError as e:
        print("Oops!..", e)
