echo ETSI-SSP-CI-private-key >summary.txt
openssl ec -inform DER -in private_keys/ETSI-SSP-CI-private-key.der -text >>summary.txt
echo ETSI-SSP-AAA-CA-private-key >>summary.txt
openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-CA-private-key.der -text >>summary.txt
echo ETSI-SSP-AAA-EE-private-key >>summary.txt
openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-EE-private-key.der -text >>summary.txt
echo ETSI-SSP-AAS-CA-private-key >>summary.txt
openssl ec -inform DER -in private_keys/ETSI-SSP-AAS-CA-private-key.der -text >>summary.txt
echo ETSI-SSP-AAS-EE-private-key >>summary.txt
openssl ec -inform DER -in private_keys/ETSI-SSP-AAS-EE-private-key.der -text >>summary.txt
echo ETSI-SSP-AAA-CA-FAKE-private-key >>summary.txt
openssl ec -inform DER -in private_keys/ETSI-SSP-AAA-CA-FAKE-private-key.der -text >>summary.txt

echo ETSI-SSP-CI-public-key >>summary.txt
openssl ec -inform der -in private_keys/ETSI-SSP-CI-private-key.der      -pubout -text >>summary.txt
echo ETSI-SSP-AAA-CA-public-key >>summary.txt
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-CA-private-key.der  -pubout -text >>summary.txt
echo ETSI-SSP-AAA-EE-public-key >>summary.txt
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-EE-private-key.der  -pubout -text >>summary.txt
echo ETSI-SSP-AAS-CA-public-key >>summary.txt
openssl ec -inform der -in private_keys/ETSI-SSP-AAS-CA-private-key.der  -pubout -text >>summary.txt
echo ETSI-SSP-AAS-EE-public-key >>summary.txt
openssl ec -inform der -in private_keys/ETSI-SSP-AAS-EE-private-key.der  -pubout -text >>summary.txt
echo ETSI-SSP-AAA-CA-FAKE-public-key >>summary.txt
openssl ec -inform der -in private_keys/ETSI-SSP-AAA-CA-FAKE-private-key.der  -pubout -text >>summary.txt

echo certificates/ETSI-SSP-CI.pem >>summary.txt
openssl x509 -in certificates/ETSI-SSP-CI.pem -text >>summary.txt
echo certificates/ETSI-SSP-AAA-CA.pem >>summary.txt
openssl x509 -in certificates/ETSI-SSP-AAA-CA.pem -text >>summary.txt
echo certificates/ETSI-SSP-AAS-CA.pem >>summary.txt
openssl x509 -in certificates/ETSI-SSP-AAS-CA.pem -text >>summary.txt
echo certificates/ETSI-SSP-AAA-EE.pem >>summary.txt
openssl x509 -in certificates/ETSI-SSP-AAA-EE.pem -text >>summary.txt
echo certificates/ETSI-SSP-AAS-EE.pem >>summary.txt
openssl x509 -in certificates/ETSI-SSP-AAS-EE.pem -text >>summary.txt

echo certificates/ETSI-SSP-AAA-EE-FAKE.pem >>summary.txt
openssl x509 -in certificates/ETSI-SSP-AAA-EE-FAKE.pem -text >>summary.txt