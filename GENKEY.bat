clear
echo del private_keys/*.*
del public_keys/*.*
echo openssl ecparam -name brainpoolP384r1 -genkey -noout -outform der -out private_keys/ETSI-SSP-CI-private-key.der  
echo openssl ecparam -name brainpoolP384r1 -genkey -noout -outform der -out private_keys/ETSI-SSP-AAA-CA-private-key.der  
echo openssl ecparam -name brainpoolP384r1 -genkey -noout -outform der -out private_keys/ETSI-SSP-AAA-EE-private-key.der  
echo openssl ecparam -name brainpoolP384r1 -genkey -noout -outform der -out private_keys/ETSI-SSP-AAS-CA-private-key.der  
echo openssl ecparam -name brainpoolP384r1 -genkey -noout -outform der -out private_keys/ETSI-SSP-AAS-EE-private-key.der 
openssl ecparam -name brainpoolP384r1 -genkey -noout -outform der -out private_keys/ETSI-SSP-AAA-CA-FAKE-private-key.der  

openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-CA-private-key.der -outform PEM -out private_keys/ETSI-SSP-AAA-CA-FAKE-private-key.pem
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-CA-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAA-CA-FAKE-public-key.der 

openssl ec -inform DER -in private_keys/ETSI-SSP-CI-private-key.der -outform PEM -out private_keys/ETSI-SSP-CI-private-key.pem
openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-CA-private-key.der -outform PEM -out private_keys/ETSI-SSP-AAA-CA-private-key.pem
openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-EE-private-key.der -outform PEM -out private_keys/ETSI-SSP-AAA-EE-private-key.pem
openssl ec -inform DER -in private_keys/ETSI-SSP-AAS-CA-private-key.der -outform PEM -out private_keys/ETSI-SSP-AAS-CA-private-key.pem
openssl ec -inform DER -in private_keys/ETSI-SSP-AAS-EE-private-key.der -outform PEM -out private_keys/ETSI-SSP-AAS-EE-private-key.pem
openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-CA-private-key.der -outform PEM -out private_keys/ETSI-SSP-AAA-CA-private-key.pem

openssl ec -inform der -in private_keys/ETSI-SSP-CI-private-key.der      -pubout -outform der -out public_keys/ETSI-SSP-CI-public-key.der 
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-CA-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAA-CA-public-key.der 
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-CA-FAKE-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAA-CA-FAKE-public-key.der 
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-EE-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAA-EE-public-key.der 
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-EE-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAA-EE-FAKE-public-key.der 
openssl ec -inform der -in private_keys/ETSI-SSP-AAS-CA-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAS-CA-public-key.der 
openssl ec -inform der -in private_keys/ETSI-SSP-AAS-EE-private-key.der  -pubout -outform der -out public_keys/ETSI-SSP-AAS-EE-public-key.der 

openssl ec -inform der -in private_keys/ETSI-SSP-CI-private-key.der      -pubout -outform pem -out public_keys/ETSI-SSP-CI-public-key.pem 
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-CA-private-key.der  -pubout -outform pem -out public_keys/ETSI-SSP-AAA-CA-public-key.pem 
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-EE-private-key.der  -pubout -outform pem -out public_keys/ETSI-SSP-AAA-EE-public-key.pem 
openssl ec -inform der -in private_keys/ETSI-SSP-AAS-CA-private-key.der  -pubout -outform pem -out public_keys/ETSI-SSP-AAS-CA-public-key.pem 
openssl ec -inform der -in private_keys/ETSI-SSP-AAS-EE-private-key.der  -pubout -outform pem -out public_keys/ETSI-SSP-AAS-EE-public-key.pem 

 

dir private_keys
dir public_keys

echo openssl x509 -in ETSI-SSP-AAS-EE.asn -inform der -text
echo openssl x509 -text -in certificates/ETSI-SSP-AAA-CA.crt -noout