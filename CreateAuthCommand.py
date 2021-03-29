
import asn1tools
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

import constante as cts
from CreateCertificate import PrivateKey
from ui import UI

AAS_MODEL = ['RFC5280.asn', 'RFC3279.asn', 'SSP_ASN.asn']


class SSPAuthenticationCommand:
    """Base class for a handling a SSP token."""

    def __init__(self):
        """Instantiate the object."""
        self.setModel(AAS_MODEL)

    def setModel(self, modeles):
        """Set the ASN.1 model."""
        self.model = asn1tools.compile_files(modeles, 'der')
        # for type in self.model.types:
        #     print(type)

    def generateChallengeCommand(self, parameters=None):
        """ Generate the AAS-OP-GET-CHALLENGE-Service-Command."""
        m_aas_command = self.model.encode(
            'AAS-CONTROL-SERVICE-GATE-Commands',
            ('aAAS-OP-GET-CHALLENGE-Service-Command', {})
            )
        with open(cts.PATH_CREDENTIALS +
                  "aAAS-OP-GET-CHALLENGE-Service-Command" +
                  ".der", "wb") as f:
            f.write(m_aas_command)

    def generateChallengeResponse(self, parameters=None):
        """ Generate the AAS-OP-GET-CHALLENGE-Service-Response."""
        with open(cts.PATH_CREDENTIALS + "CP_AAS" +
                  ".der", "rb") as f:
            aCertificates = f.read()
        m_aCertificates = self.model.decode('Certificates', aCertificates)
        with open(cts.PATH_CREDENTIALS + "AAS01" +
                  ".bin", "rb") as f:
            aChallenge = f.read()

        m_aas_response = self.model.encode(
            'AAS-CONTROL-SERVICE-GATE-Responses',
            ('aAAS-OP-GET-CHALLENGE-Service-Response',
                {'aParameter': {'aChallenge': aChallenge,
                                'aCertificates': m_aCertificates
                                }
                 }))
        with open(cts.PATH_CREDENTIALS + "aAAS-OP-GET-CHALLENGE-Service-Response" +
                  ".der", "wb") as f:
            f.write(m_aas_response)

    def readChallengeResponse(self, parameters=None):
        """ Read the AAS-OP-GET-CHALLENGE-Service-Response."""
        with open(cts.PATH_CREDENTIALS + "aAAS-OP-GET-CHALLENGE-Service-Response" +
                  ".der", "rb") as f:
            aResponse = f.read()
        m_aResponse = self.model.decode('AAS-CONTROL-SERVICE-GATE-Responses',
                                        aResponse)
        mCert509dict = {}
        for certificate in m_aResponse[1]['aParameter']['aCertificates']:
            der_data = self.model.encode('Certificate', certificate)
            cert = x509.load_der_x509_certificate(der_data, default_backend())
            CN = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            mCert509dict[CN[0].value] = cert

        for k in mCert509dict:
            v = mCert509dict[k]
            CN = v.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_issuer = mCert509dict[CN[0].value]
            public_key_issuer = cert_issuer.public_key()
            print(k, " verified by:", CN[0].value)
            public_key_issuer.verify(
                v.signature,
                v.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
                )
        print(m_aResponse)

    def generateAuthenticateCommand(self, public_key):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Command."""
        with open(cts.PATH_CREDENTIALS + "CP_AAA" +
                  ".der", "rb") as f:
            aCertificates = f.read()
        m_aCertificates = self.model.decode('Certificates', aCertificates)
        with open(cts.PATH_CREDENTIALS + "ATK-AAA-ECKA" +
                  ".der", "rb") as f:
            aToken_der = f.read()
            m_aaa_token = self.model.decode('AuthenticationToken', aToken_der)
            m_aas_command = self.model.encode(
                'AAS-CONTROL-SERVICE-GATE-Commands',
                'aAAS-OP-AUTHENTICATE-Service-Command', {
                 'aCredential': {
                    'aAccessorTokenCredential': {
                        'aToken': m_aaa_token,
                        'aTokenCertificationPath': m_aCertificates
                        }
                    }
                }
            )
            with open(cts.PATH_CREDENTIALS +
                      "aAAS-OP-AUTHENTICATE-Service-Command.der",
                      "wb") as f:
                f.write(m_aas_command)

    def generateAuthenticateResponse(self, parameters):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Response."""
        pass

    def generateSharedSecret(self, public_key):

        m_atk_aaa_private_key = PrivateKey('ATK-AAA-ECKA').get()
        shared_key = m_atk_aaa_private_key.exchange(
            ec.ECDH(), public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)


# Open the YAML parameter file
AUTHCONFIGURATION = {
    'options': 'c:h:i:o',
    'description': ["ifile=", "ofile=", "ccommand="],
    'usage': 'CreateAuthCommand.py -c <command> [-i <inputfile>] [-o <outputfile>]'
}
if __name__ == "__main__":
    try:
        my_ui = UI(AUTHCONFIGURATION)
        m_auth = SSPAuthenticationCommand()
        if my_ui.isInputFile():
            f = open(my_ui.getInputFile(), 'r', encoding='utf-8')
            # Load the YAML file containing the parameters.
            paths = list(yaml.load_all(f, Loader=yaml.FullLoader))
            f.close()
        if my_ui.getCommand() == "challenge":
            m_auth.generateChallengeResponse()
            m_auth.readChallengeResponse()
            m_auth.generateAuthenticateCommand()
    
    except ValueError as e:
        print("Oops!..", e)
