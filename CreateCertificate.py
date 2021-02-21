from OpenSSL import crypto
from socket import gethostname
import yaml


class PublicKey:
    def __init__(self, name):
        f = open("public_keys/"+name+"-public-key.pem")
        buf = f.read()
        f.close()
        self.public_key= crypto.load_publickey(crypto.FILETYPE_PEM, buf)    
    def get(self):
        return self.public_key

class PrivateKey:
    def __init__(self, name):
        f = open("private_keys/"+name+"-private-key.pem")
        buf = f.read()
        f.close()
        self.private_key= crypto.load_privatekey(crypto.FILETYPE_PEM, buf)    
    def get(self):
        return self.private_key

class SSPcertificate:
    curve_name = "brainpoolP384r1"

    def __init__(self):
        pass

    def generate (self, certificate_parameter):
        cert = crypto.X509()
        self.cert_name= certificate_parameter['Name']
        self.public_key  = PublicKey(self.cert_name)
        self.private_key = PrivateKey(self.cert_name)

        print ("certificate parameter",certificate_parameter)
        for k, m_field in certificate_parameter.items():
            print(k, "--->", m_field)
            if k == "subject" :
                for k, v in m_field.items():
                    print(k, "<-->", v)
                    if k == "C" :
                        cert.get_subject().C = v
                    if k == "ST" :   
                        cert.get_subject().ST = v
                    if k == "O"  :  
                        cert.get_subject().O = v
                    if k== "OU":
                        cert.get_subject().OU = v
                    if k == "CN" :    
                        cert.get_subject().CN = v
            if k == "serial_number" :
                cert.set_serial_number(m_field)
            if k == "not_before":    
                cert.set_notBefore(bytes(m_field, 'utf-8'))
            if k == "not_after":    
                cert.set_notAfter(bytes(m_field, 'utf-8'))   
            if k == "extensions":
                for k, v in m_field.items():
                    print(k, "<-->", v)
                    if (v["subject"] is None) and (v["issuer"] is None):
                        extension = crypto.X509Extension(
                            bytes(v["type_name"],'utf-8'),
                            v["critical"],
                            bytes(v["value"],'utf-8'),
                        )
                        cert.add_extensions([extension])
                    if (v["subject"] is not None) and (v["issuer"] is not None):
                        extension = crypto.X509Extension(
                            bytes(v["type_name"],'utf-8'),
                            v["critical"],
                            bytes(v["value"],'utf-8'),
                            bytes(v["subject"],'utf-8'),
                            bytes(v["issuer"],'utf-8')
                        )
                        cert.add_extensions([extension])
                    if (v["subject"] is not None) and (v["issuer"] is None):
                        extension = crypto.X509Extension(
                            bytes(v["type_name"],'utf-8'),
                            v["critical"],
                            bytes(v["value"],'utf-8'),
                            bytes(v["subject"],'utf-8')
                        )
                        cert.add_extensions([extension])
                    if (v["subject"] is  None) and (v["issuer"] is not None):
                        extension = crypto.X509Extension(
                            bytes(v["type_name"],'utf-8'),
                            v["critical"],
                            bytes(v["value"],'utf-8'),
                            bytes(v["issuer"],'utf-8')
                        )                        
                        cert.add_extensions([extension])

        cert.set_issuer(cert.get_subject())  # self-sign self certificate
        cert.set_pubkey(self.public_key.get())
        sig=cert.sign(self.private_key.get(), 'sha256')
        # pass certificate around, but of course keep private.key
        open("certificates/"+self.cert_name+".crt", 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open("certificates/"+self.cert_name+".der", 'wb').write(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))
        # Now the real world use case; use certificate to verify signature




with open("ETSI-SSP-CI-param.yaml", 'r') as f:
    paths = yaml.load_all(f, Loader=yaml.FullLoader)
    for path in paths:
        for k,v in path.items():
            print(k, ":->", v)
            print("Cert name: "+v["Name"])
            m_cert = SSPcertificate()
            m_cert.generate(v)

    #m_cert= SSPcertificate(parameter["Name"])
    # for k, v in parameter.items():
    #     print(k, "->", v)

# m_cert.generate()

# f = open("CA.crt")
# ca_buf = f.read()
# f.close()
# ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_buf)


# f = open("selfsign.crt")
# ss_buf = f.read()
# f.close()
# ss_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ss_buf)


# crypto.verify(ca_cert, ss_cert.signature, ss_cert.data,ss_cert.digest)
