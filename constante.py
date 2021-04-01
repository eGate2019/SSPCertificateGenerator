from cryptography.hazmat.primitives.asymmetric import ec
OID_PUBLICKEY = '1.2.840.10045.2.1'
OID_BRAINPOOLP384R1 = '1.3.36.3.3.2.8.1.1.11'
KEY_SIZE_E128 = 0   # Key_Size e128
KEY_SIZE_E256 = 1  # Key_Size e256
AES_CGM = 0  # aAES-CGM-StreamCipherIdentifier
OID_ECDSASHA256 = '1.2.840.10045.4.3.2'  # ecdsa-with-SHA256(2)
OID_AKI = '2.5.29.35'  # Authority Key Identifier
V1 = 0  # Version 1
CURVES = {'BrainpoolP256R1': ec.BrainpoolP256R1,
          'BrainpoolP384R1': ec.BrainpoolP384R1,
          'NIST P-256': ec.SECP256R1,
          'NIST P-384': ec.SECP384R1
          }
KEY_SIZES = {
            128: KEY_SIZE_E128,
            256: KEY_SIZE_E256
            }
# Keywords in the Yaml configuration file

KW_AUTHENTICATIONTOKEN = 'AuthenticationToken'
KW_AUTHENTICATIONTOKENCREDENTIALS = 'AuthenticationTokenCredentials'
KW_BASICCONSTRAINTS = 'BasicConstraints'
KW_C = 'C'
KW_CA = 'CA'
KW_CERTIFICATE = 'Certificate'
KW_CERTIFICATEPOLICIES = 'CertificatePolicies'
KW_CERTIFICATIONPATH = 'CertificationPath'
KW_CHALLENGE = 'Challenge'
KW_CN = 'CN'
KW_CRITICAL = 'Critical'
KW_DECRYPT = 'Decrypt'
KW_ECKA_CURVE = 'ECKA-Curve'
KW_ENCRYPT = 'Encrypt'
KW_EXPLICIT_TEXT = 'Explicit_text'
KW_EXTENSIONS = 'Extensions'
KW_GENERATE = 'Generate'
KW_IDENTIFIER = 'Identifier'
KW_IN = 'In'
KW_ISSUER = 'Issuer'
KW_KEYSIZE = 'KeySize'
KW_LN = 'LN'
KW_MODELES = 'Modeles'
KW_MTU = 'MTU'
KW_NAME = 'Name'
KW_NOT_AFTER = 'Not_after'
KW_NOT_BEFORE = 'Not_before'
KW_O = 'O'
KW_OU = 'OU'
KW_OUT = 'Out'
KW_PATH = 'Path'
KW_PATHLEN = 'Pathlen'
KW_SEQUENCE = 'Sequence'
KW_SERIAL_NUMBER = 'Serial_number'
KW_ST = 'ST'
KW_SUBJECT = 'Subject'
KW_VALUE = 'Value'
KW_CHALLENGE_COMMAND = 'Challenge command'
KW_CHALLENGE_RESPONSE = 'Challenge response'
KW_AUTHENTICATION_COMMAND = 'Authenticate command'
KW_AUTHENTICATION_RESPONSE = 'Authenticate response'
KW_ATK_CREDENTIALS = 'Authentication Credentials'
KW_READ_CHALLENGE_RESPONSE = 'Read Challenge response'
KW_GENERATE_SHARED_KEY = 'Generate shared key'
KW_PRIVATE = 'Private'
KW_PUBLIC = 'Public'
KW_DIVERSIFIER = 'Diversifier'
# Paths of the folders

PATH_PRIVATE = 'private_keys/'
PATH_PUBLIC = 'public_keys/'
PATH_CERTIFICATES = 'certificates/'
PATH_TOKENS = 'tokens/'
PATH_CREDENTIALS = 'credentials/'

# SI information for derivation keys
SI128 = b'\x10\x90\x10'
SI256 = b'\x20\x90\x20'
SI_KEYS = {KEY_SIZE_E128: SI128, KEY_SIZE_E256: SI256}
MD_LENGTH = {KEY_SIZE_E128: 32, KEY_SIZE_E256: 48}
# secure SCL
SCL_SIZE_SEQ = 4  # Size of SEQ field (32 bit) in the secure SCL message
