
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



class SSPAuthenticationCommand:
    """Base class for a handling a SSP token."""

    def __init__(self, path):
        """Instantiate the object."""
        self.path = path

    def setModel(self, modeles):
        """Set the ASN.1 model."""
        self.model = asn1tools.compile_files(modeles, 'der')
    
    def generateChallengeCommand(self, parameters):
        """ Generate the AAS-OP-GET-CHALLENGE-Service-Command."""
        pass
    
    def generateChallengeResponse(self, parameters):
        """ Generate the AAS-OP-GET-CHALLENGE-Service-Response."""
        pass
    
    def generateAuthenticateCommand(self, parameters):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Command."""
        pass
    
    def generateAuthenticateResponse(self, parameters):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Response."""
        pass



# Open the YAML parameter file
defaultConfiguration = {
    'options':'hic:o',
    'description':["ifile=", "ofile=","ccommand="],
    'usage':'CreateToken.py -c [-i <inputfile>] [-o <outputfile>]'
}
if __name__ == "__main__":
    try:
        my_ui = UI(configuration=defaultConfiguration)
        if my_ui.isInputFile():
            f = open(my_ui.getInputFile(), 'r', encoding='utf-8')
            # Load the YAML file containing the parameters.
            paths = list(yaml.load_all(f, Loader=yaml.FullLoader))
            f.close()

    except ValueError as e:
        print("Oops!..", e)
