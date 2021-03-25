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
