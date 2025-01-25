import os, subprocess, re, base64, binascii, json, hashlib, time, argparse, textwrap
from urllib.request import urlopen, Request

class SchnuBbySSL:
    def __init__(self, openssl, email, accountKeyFile, csrFile):
        self.directoryUrl = 'https://acme-v02.api.letsencrypt.org/directory'
        self.requestOK = [200, 201, 204]
        self.openssl = openssl
        self.accountKeyFile = accountKeyFile
        self.csrFile = csrFile
        self.directory = None
        self.alg = None
        self.jwk = None
        self.thumbprint = None
        self.accountUrl = None
        self.order = None
        self.orderUrl = None
        self.orderPayload = None
        self.email = email
        self.der = None
        self.colorsOk = ''
        self.colorsWarn = ''
        self.colorsFail = ''
        self.colorsNc = ''
#        self.colorsOk = '\033[92m'
#        self.colorsWarn = '\033[93m'
#        self.colorsFail = '\033[91m'
#        self.colorsNc = '\033[0m'
        self.opensslCmd = None
        self.authorizations = None
        self.challengeFileName = None
        self.challengeFileContent = None

    def b64(self, b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")
    def request(self, url, data=None):
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json"}))
            resp_data, resp_code, resp_headers = resp.read().decode('utf8'), resp.getcode(), resp.headers
            if resp_code not in self.requestOK:
                print('FEHLER BEI REQUEST!!')
                exit(1)
            try:
                resp_data = json.loads(resp_data)
            except ValueError:
                pass               
            return(resp_data, resp_code, resp_headers)
    def createSignature(self):
        proc = subprocess.Popen([self.openssl, 'dgst', '-sha256', '-hex', '-sign', self.accountKeyFile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(self.opensslCmd)
        out = re.search(r'(?:\(stdin\)= |)([a-f0-9]{512,1024})', out.decode('utf8')).group(1)
        return self.b64(binascii.unhexlify(('0' + out if len(out) %2 != 0 else out)))
    def sendSignedRequest(self, url, payload=None):
        protected = {'url': url, 'alg': self.alg, 'nonce': self.request(self.directory['newNonce'])[2]['Replay-Nonce']}
        protected.update({'jwk': self.jwk} if self.accountUrl is None else {'kid': self.accountUrl})
        protected, _payload = self.b64(json.dumps(protected).encode('utf8')), "" if payload is None else self.b64(json.dumps(payload).encode('utf8'))
        self.opensslCmd = '{0}.{1}'.format(protected, _payload).encode('utf8')
        return self.request(url, data={json.dumps({'protected': protected, 'payload': _payload, 'signature': self.createSignature()}).encode('utf8')})
    def _poll_until_not(self, url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - t0 < 3600), "Polling timeout" # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = self.sendSignedRequest(url)
        return result


    def readAccountKey(self):
        print('[{0}LAEUFT{1}] Lese Account Key...'.format(self.colorsWarn, self.colorsNc), end='\r')
        proc = subprocess.Popen([self.openssl, 'rsa', '-in', self.accountKeyFile, '-noout', '-text'], stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        pubHex, pubExp = re.search(r'modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)', out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
        pubExp = '{0:x}'.format(int(pubExp))
        pubExp = '0{0}'.format(pubExp) if len(pubExp) % 2 else pubExp
        self.alg, self.jwk = 'RS256', {
            'e': self.b64(binascii.unhexlify(pubExp.encode('utf-8'))),
            'kty': 'RSA',
            'n': self.b64(binascii.unhexlify(re.sub(r'(\s|:)', '', pubHex).encode('utf-8'))),
        }
        accountkey_json = json.dumps(self.jwk, sort_keys=True, separators=(',', ':'))
        self.thumbprint = self.b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
        print('[  {0}OK{1}  ] Lese Account Key...'.format(self.colorsOk, self.colorsNc), end='\n')
    def readCSR(self):
        print('[{0}LAEUFT{1}] Lese CSR...'.format(self.colorsWarn, self.colorsNc), end='\r')
        proc = subprocess.Popen([self.openssl, "req", "-in", self.csrFile, "-noout", "-text"], stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        domains = set([])
        common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
        if common_name is not None:
            domains.add(common_name.group(1))
        subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])
        self.orderPayload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        self.directory = self.request(self.directoryUrl)[0]
        print('[  {0}OK{1}  ] Lese CSR...'.format(self.colorsOk, self.colorsNc), end='\n')
    def signRequests(self):
            print('[{0}LAEUFT{1}] Signiere Requests...'.format(self.colorsWarn, self.colorsNc), end='\r')
            self.accountUrl = self.sendSignedRequest(self.directory['newAccount'], payload={'termsOfServiceAgreed': True})[2]['Location']
            self.sendSignedRequest(self.accountUrl, payload={'contact': ['mailto:' + self.email]})
            self.order, _, self.orderUrl = self.sendSignedRequest(self.directory['newOrder'], self.orderPayload)
            self.orderUrl = self.orderUrl['Location']
            print('[  {0}OK{1}  ] Signiere Requests...'.format(self.colorsOk, self.colorsNc), end='\n')
    def validateAuthorization(self):
            ## TODO ACME Pfad als Param
            ## TODO Wenn nicht alle challenges valid sind, muss der Apache bereits gestellt werden.
            print('[{0}LAEUFT{1}] Validiere Serverbesitz...'.format(self.colorsWarn, self.colorsNc), end='\r')
            for authUrl in self.order['authorizations']:
                auth, _, _ = self.sendSignedRequest(authUrl)
                domain = auth['identifier']['value']
                if auth['status'] == 'valid':
                    continue
                challenge = [c for c in auth['challenges'] if c['type'] == 'http-01'][0]
                token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
                authKey = '{0}.{1}'.format(token, self.thumbprint)
                print('File:{0}\nContent:{1}'.format(token, authKey))
            print('[  {0}OK{1}  ] Validiere Serverbesitz...'.format(self.colorsOk, self.colorsNc), end='\n')        
    def signCertificate(self):
        ## TODO die Dateien müssen zu den jeweiligen Servern kopiert werden und diese dann (neu)gestartet werden.
        print('[{0}LAEUFT{1}] Erstelle signiertes Zertifikat...'.format(self.colorsWarn, self.colorsNc), end='\r')        
        proc = subprocess.Popen([self.openssl, "req", "-in", self.csrFile, "-outform", "DER"], stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        self.sendSignedRequest(self.order['finalize'], {"csr": self.b64(out)})        
        self.order = self._poll_until_not(self.orderUrl, ["pending", "processing"], "Error checking order status")
        if self.order['status'] != "valid":
            raise ValueError("Order failed: {0}".format(self.order))
        certificate_pem, _, _ = self.sendSignedRequest(self.order['certificate'])
        with open('domain.crt', 'w') as f:
            f.write('{0}'.format(certificate_pem.split("-----END CERTIFICATE-----")[0]+"-----END CERTIFICATE-----"))
            f.close()
        with open('intermediate.pem', 'w') as f:
            f.write('{0}'.format(certificate_pem.split("-----END CERTIFICATE-----")[1]+"-----END CERTIFICATE-----"))
            f.close()
        print('[  {0}OK{1}  ] Erstelle signiertes Zertifikat...'.format(self.colorsWarn, self.colorsNc), end='\r')

            
def main(argv=None):
    #cert = SchnuBbySSL('C:/OpenSSL-Win64/bin/openssl.exe', 'mflix1337@gmail.com', 'account.key', 'domain.csr')
    cert = SchnuBbySSL('C:/Program Files/OpenSSL-Win64/bin/openssl.exe', 'mflix1337@gmail.com', 'account.key', 'domain.csr', 'C:/Users/Server-Admin/Desktop/Server Programme/xampp')
    #/htdocs/.well-known/acme-challenge
    #/apache/conf
    #httpd.conf
    #httpd_acme.conf
    #/apache/conf/ssl.key/domain.key
    #/apache/conf/ssl.crt/domain.crt // intermediate.pem
    #node.exe 2x
    #httpd.exe 2x
    cert.readAccountKey()
    cert.readCSR()
    cert.signRequests()
    cert.validateAuthorization()
    cert.signCertificate()
    
if __name__ == '__main__':
    main()
