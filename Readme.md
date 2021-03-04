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

    AAA: # certification path name
        - certificate:
            extensions:
                CertificatePolicies:
                    critical: true
                    value:
                        identifier: 0.4.0.3666.1
                        explicit_text: id-role
                basicConstraints:
                    critical: true
                    value:
                        CA: true
                        pathlen: 1
            Name: ETSI-SSP-CI  # Base name of the certificate
            serial_number: 1
            not_after: '2021-12-01T12:00:00'
            issuer: ETSI-SSP-CI  # Base name of the issuer's keys
            not_before: '2021-01-01T12:00:00'
            subject:
                C: FR
                ST: PACA
                CN: ETSI.ORG
                O: ETSI-SSP-TTF
                OU: ETSI