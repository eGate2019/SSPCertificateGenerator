# ETSI SSP TTF x509 certificates generation
## Overview
This set of programs and files aims at generating the x509v3 certificates used for the Accessor Authentication Service as described in the annex C of the [TS 103.666 part 1 V15.2.0  (2020-04)](https://www.etsi.org/deliver/etsi_ts/103600_103699/10366601/15.00.00_60/ts_10366601v150000p.pdf) .
## Installation
OpenSSL 3.0.0 shall be installed. The guidline for performing the installation are availabe in [OpenSSL](https://www.openssl.org)
Python Cryptography package shall be installed. The guidline for performing the installation are availabe in [Cryptography.io](https://cryptography.io/en/latest/installation.html) .
## Generation of the private and public keys
The batch file GENKEY.bat contains the OpenSSL instruction for generating the private and public keys acccording to the the annex C of the TS 103.666 part 1.
The following shell command shall be executed.

`./GENKEY.bat`

## Generation of the cerficates
The followint command shall be executed.

`python3 CreateCertificate.py -i <parameters_file.yaml`

The **parameters_file.yaml** contains the certificate parameters.
The certificates are generated and stored in the **./certificates** directory with the DER and PEM format.
The human readable visualization is possible on the following web site [Certlogic](https://certlogik.com/decoder)
## Certificate parameters
Each certificate has its parameters in a YAML structure in a YAML file.
As example, the YAML structure of the AAS certification path from the CI to the End Entity certificate is the following:
