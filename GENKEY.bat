
openssl ecparam -name brainpoolP384r1 -genkey -noout -out ETSI-SSP-CI-private-key.pem -param_enc explicit
openssl ecparam -name brainpoolP384r1 -genkey -noout -out ETSI-SSP-AAA-CA-private-key.pem -param_enc explicit
openssl ecparam -name brainpoolP384r1 -genkey -noout -out ETSI-SSP-AAA-EE-private-key.pem -param_enc explicit
openssl ecparam -name brainpoolP384r1 -genkey -noout -out ETSI-SSP-AAS-CA-private-key.pem -param_enc explicit
openssl ecparam -name brainpoolP384r1 -genkey -noout -out ETSI-SSP-AAS-EE-private-key.pem -param_enc explicit

openssl ec -in ETSI-SSP-CI-private-key.pem      -pubout -out ETSI-SSP-CI-public-key.pem
openssl ec -in ETSI-SSP-AAA-CA-private-key.pem  -pubout -out ETSI-SSP-AAA-CA-public-key.pem
openssl ec -in ETSI-SSP-AAA-EE-private-key.pem  -pubout -out ETSI-SSP-AAA-EE-public-key.pem
openssl ec -in ETSI-SSP-AAS-CA-private-key.pem  -pubout -out ETSI-SSP-AAS-CA-public-key.pem
openssl ec -in ETSI-SSP-AAS-EE-private-key.pem  -pubout -out ETSI-SSP-AAS-EE-public-key.pem

mv *-private-key.pem private_keys/
mv *-public-key.pem public_keys/

ls private_keys
ls public_keys

echo openssl x509 -in ETSI-SSP-AAS-EE.asn -inform der -text
echo openssl x509 -text -in certificates/ETSI-SSP-AAA-CA.crt -noout