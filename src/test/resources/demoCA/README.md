### Host the CRL

```bash
cd crl
python3 -m http.server 8000 -b localhost
```

### Generate a new PKCS#12 file

This creates a new key, a certificate for the key and combines them in a PKCS#12 file in the parent directory. From this directory:

```bash
NAME=sample

## generate private key
openssl genrsa -out certs/$NAME.key.pem 4096

## generate certificate signing request
openssl req -new -key certs/$NAME.key.pem -out certs/$NAME.csr

## generate and sign the certificate using rootca certificate
openssl ca -config openssl.cnf -notext -batch -in certs/$NAME.csr -out certs/$NAME.crt -extfile ext_template.cnf

## generate pkcs#12 file from key and certificate
openssl pkcs12 -export -out ../$NAME.p12 -inkey certs/$NAME.key.pem -in certs/$NAME.crt -certfile cacert.pem
```

### Revoke a certificate

Revoke the certificate:

```bash
openssl ca -config openssl.cnf -revoke certs/sample.crt
```

Update the CRL:

```bash
openssl ca -config openssl.cnf -gencrl -out crl/rootca.crl
```

### Regenerate the CA Certificate

```bash
openssl req -new -x509 -days 3650  -config openssl.cnf  -key private/cakey.pem -out cacert.pem
```
