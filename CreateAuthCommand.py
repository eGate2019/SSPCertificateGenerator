
import asn1tools
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
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
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_PATH] +
                  ".der", "rb") as f:
            aCertificates = f.read()
        m_aCertificates = self.model.decode('Certificates', aCertificates)
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_CHALLENGE] +
                  ".bin", "rb") as f:
            aChallenge = f.read()

        m_aas_response = self.model.encode(
            'AAS-CONTROL-SERVICE-GATE-Responses',
            ('aAAS-OP-GET-CHALLENGE-Service-Response',
                {'aParameter': {'aChallenge': aChallenge,
                                'aCertificates': m_aCertificates
                                }
                 }))
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                  ".der", "wb") as f:
            f.write(m_aas_response)

    def readChallengeResponse(self, parameters=None):
        """ Read the AAS-OP-GET-CHALLENGE-Service-Response."""
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
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


    def generateAuthenticateCommand(self, parameters=None):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Command."""
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_PATH] +
                  ".der", "rb") as f:
            aCertificates_der = f.read()
        m_aCertificates = self.model.decode('Certificates', aCertificates_der)
        with open(cts.PATH_TOKENS + parameters[cts.KW_AUTHENTICATIONTOKEN] +
                  ".der", "rb") as f:
            aToken_der = f.read()
            m_aaa_token = self.model.decode('AuthenticationToken', aToken_der)

            m_aaa_token_param = {'aCredential': (
                    'aAccessorTokenCredential', {
                        'aToken': m_aaa_token,
                        'aTokenCertificationPath': m_aCertificates
                        }
                    )
            }

            m_aas_command = self.model.encode(
                'AAS-CONTROL-SERVICE-GATE-Commands',
                ('aAAS-OP-AUTHENTICATE-ACCESSOR-Service-Command',
                 m_aaa_token_param)
                )

            with open(cts.PATH_CREDENTIALS +
                      "aAAS-OP-AUTHENTICATE-Service-Command.der",
                      "wb") as f:
                f.write(m_aas_command)

    def generateAuthenticateResponse(self, parameters=None):
        """ Generate the AAS-OP-AUTHENTICATE-Service-Response."""
        with open(cts.PATH_TOKENS + parameters[cts.KW_AUTHENTICATIONTOKEN] +
                  ".der", "rb") as f:
            aToken_der = f.read()
            m_aaa_token = self.model.decode('AuthenticationToken', aToken_der)
            m_aas_command = self.model.encode(
                'AAS-CONTROL-SERVICE-GATE-Responses',
                ('aAAS-OP-AUTHENTICATE-ACCESSOR-Service-Response', {
                 'aParameter': ('aServiceToken', m_aaa_token)
                 }
                 )
            )
            with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                      ".der",
                      "wb") as f:
                f.write(m_aas_command)

    def generateSharedSecret(self, parameters=None):
        """Generate the shared secret."""

        m_private_key = PrivateKey(parameters[cts.KW_PRIVATE]).get()
        # Read the authentication token
        with open(cts.PATH_TOKENS + parameters[cts.KW_PUBLIC] +
                  ".der", "rb") as f:
            aToken_der = f.read()
            # Extract the authentication token with its model
            m_token = self.model.decode('AuthenticationToken', aToken_der)
        # Convert the public key info from a model to a DER
        m_pk_der = self.model.encode('SubjectPublicKeyInfo',
                                     m_token['tbsToken']['subjectPublicKeyInfo'])
        # Retrieve the public key from the DER file
        m_public_key = serialization.load_der_public_key(
                m_pk_der, backend=default_backend()
            )
        # Extract the key size for the streamcipher
        m_key_size_idx = m_token['tbsToken']['aATK-Content']['aKey-Size']
        # Compute the shared key
        shared_key = m_private_key.exchange(
            ec.ECDH(), m_public_key)
        # Compute the diversifier from aChallenge and the gate identifier.
        m_diversifier = bytes(a ^ b for (a, b) in zip(
            m_token['tbsToken']['aATK-Content']['aChallenge'],
            bytes.fromhex(parameters[cts.KW_DIVERSIFIER])))
        # Compute the shared info.
        m_SI = cts.SI_KEYS[m_key_size_idx] + m_diversifier
        # Derive the key for the shared info
        derived_key = X963KDF(
            algorithm=hashes.SHA256(),
            length=cts.MD_LENGTH[m_key_size_idx],
            sharedinfo=m_SI,
            backend=default_backend()
        ).derive(shared_key)
        # Storage of the GCM key and IV
        if m_key_size_idx == cts.KEY_SIZE_E128:
            m_gcm_key = derived_key[0:16]
            m_gcm_iv = derived_key[16:32]
        else:
            m_gcm_key = derived_key[0:32]
            m_gcm_iv = derived_key[32:48]
        m_model = asn1tools.compile_files(['SSPToken.asn'], 'der')
        m_save_der = m_model.encode('GCM-Parameters', {
            'aKey': m_gcm_key,
            'aIV': m_gcm_iv
        })
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                  ".der",
                  "wb") as f:
            f.write(m_save_der)

    def encryptLargeMessage(self, parameters=None):
        """Encrypt large message from an input file."""
        self.m_counter = parameters[cts.KW_SEQUENCE]
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                  ".der",
                  "rb") as f:
            m_data = f.read()
        m_model = asn1tools.compile_files(['SSPToken.asn'], 'der')    
        m_gcm = m_model.decode('GCM-Parameters', m_data)
        # Read IV and key
        self.m_gcm_key = m_gcm['aKey']
        self.m_gcm_iv = m_gcm['aIV']
        # Read the input file
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_IN] +
                  ".bin",
                  "rb") as f:
            m_large_message = f.read()
        m_mtu = parameters[cts.KW_MTU]
        m_nb_bloc = int((len(m_large_message)+(m_mtu-1)) / (m_mtu-1))
        m_start = 0
        m_end = 0
        # Write the encrypted output file
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_OUT] +
                  ".bin",
                  "wb") as f:
            for i in range(m_nb_bloc):
                m_end = m_start + min(len(m_large_message)-m_end, m_mtu-1)
                m = self.messageFragment(m_large_message[m_start:m_end],
                                         (i == m_nb_bloc))
                m_start = m_end
                m = self.encrypt(m)
                f.write(m)

    def decryptLargeMessage(self, parameters=None):
        """ Decrypt a large file from an input file."""
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_NAME] +
                  ".der",
                  "rb") as f:
            m_data = f.read()
        m_model = asn1tools.compile_files(['SSPToken.asn'], 'der')    
        m_gcm = m_model.decode('GCM-Parameters', m_data)
        # Read IV and key
        self.m_gcm_key = m_gcm['aKey']
        self.m_gcm_iv = m_gcm['aIV']
        # Read the encrypted input file
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_IN] +
                  ".bin",
                  "rb") as f:
            m_large_message = f.read()
        m_mtu = parameters[cts.KW_MTU]
        m_nb_bloc = int((len(m_large_message) / (m_mtu + 16 + cts.SCL_SIZE_SEQ))+1)
        m_start = 0
        m_end = 0
        # Write the plaintext output file
        with open(cts.PATH_CREDENTIALS + parameters[cts.KW_OUT] +
                  ".bin",
                  "wb") as f:
            for i in range(m_nb_bloc):
                m_end = m_start + min(len(m_large_message)-m_end, m_mtu+16 + cts.SCL_SIZE_SEQ)
                seq = m_large_message[m_start:m_start + cts.SCL_SIZE_SEQ]
                m = m_large_message[m_start + cts.SCL_SIZE_SEQ:m_end]
                m_start = m_end
                m = self.decrypt(m, seq)
                m, c = self.messageAssembly(m)
                f.write(m)

    def generateIVC(self, m_seq):
        """Generate IVC (96 bit) from IV and SEQ."""
        cipher = Cipher(
            algorithms.AES(self.m_gcm_key),
            modes.ECB(),
            backend=default_backend())
        encryptor = cipher.encryptor()
        ivc = encryptor.update(
            self.m_gcm_iv[0:16-cts.SCL_SIZE_SEQ] + m_seq
            ) + encryptor.finalize()
        return ivc[0:12]

    def messageFragment(self, message_fragment, cb):
        """ Create a message fragment."""
        PL = (len(message_fragment)+1) % 16
        if PL > 0:
            PL = 16 - PL
        if cb == 1:
            H = PL | 128
        else:
            H = PL
        m_message = message_fragment+bytes(PL)+H.to_bytes(1, byteorder='big')
        # Return the message fragment ready for encryption
        return m_message

    def messageAssembly(self, message_fragment):
        """Allow the fragment message assembly."""
        m_len_M = len(message_fragment)
        H = int.from_bytes(message_fragment[m_len_M-1:m_len_M], 'big')
        if H > 127:
            CB = True
            PL = H-128
        else:
            CB = False
            PL = H
        # return the plaintext message fragment and the chaining bit
        return message_fragment[0:m_len_M-PL-1], CB

    def encrypt(self, plaintext):
        m_seq = self.m_counter.to_bytes(cts.SCL_SIZE_SEQ, 'big')
        ivc = self.generateIVC(m_seq)
        self.encryptor = Cipher(
            algorithms.AES(self.m_gcm_key),
            modes.GCM(ivc),
            backend=default_backend()
            ).encryptor()
        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        self.encryptor.authenticate_additional_data(b'')
        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = self.encryptor.update(plaintext) +\
            self.encryptor.finalize()
        self.m_counter = self.m_counter + 1
        return (m_seq+ciphertext + self.encryptor.tag)

    def decrypt(self, ciphertext, m_seq):
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        len_cipher = len(ciphertext)
        tag = ciphertext[len_cipher-16:len_cipher]
        ctext = ciphertext[0:len_cipher-16]
        self.decryptor = Cipher(
            algorithms.AES(self.m_gcm_key),
            modes.GCM(self.generateIVC(m_seq), tag),
            backend=default_backend()
        ).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        self.decryptor.authenticate_additional_data(b'')

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return self.decryptor.update(ctext) + self.decryptor.finalize()


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
            for path in paths:
                for m_token in path:
                    parameters = path[m_token]
                    if m_token == cts.KW_CHALLENGE_COMMAND:
                        m_auth.generateChallengeCommand(parameters)
                    if m_token == cts.KW_CHALLENGE_RESPONSE:
                        m_auth.generateChallengeResponse(parameters)
                    if m_token == cts.KW_READ_CHALLENGE_RESPONSE:
                        m_auth.readChallengeResponse(parameters)
                    if m_token == cts.KW_AUTHENTICATION_COMMAND:
                        m_auth.generateAuthenticateCommand(parameters)
                    if m_token == cts.KW_AUTHENTICATION_RESPONSE:
                        m_auth.generateAuthenticateResponse(parameters)
                    if m_token == cts.KW_GENERATE_SHARED_KEY:
                        m_auth.generateSharedSecret(parameters)
                    if m_token == cts.KW_ENCRYPT:
                        m_auth.encryptLargeMessage(parameters)
                    if m_token == cts.KW_DECRYPT:
                        m_auth.decryptLargeMessage(parameters)
    except ValueError as e:
        print("Oops!..", e)
