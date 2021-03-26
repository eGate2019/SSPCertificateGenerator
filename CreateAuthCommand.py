
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
            'AAS-CONTROL-SERVICE-GATE-Commands', ('aAAS-OP-GET-CHALLENGE-Service-Command', {}))
        with open(cts.PATH_CREDENTIALS + "aAAS-OP-GET-CHALLENGE-Service-Command" +
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
        m_aResponse = self.model.decode('AAS-CONTROL-SERVICE-GATE-Responses', aResponse)
        print(m_aResponse)

    def generateAuthenticateCommand(self, parameters):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Command."""
        pass

    def generateAuthenticateResponse(self, parameters):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Response."""
        pass


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

    except ValueError as e:
        print("Oops!..", e)
