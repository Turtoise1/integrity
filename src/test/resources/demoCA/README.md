### Generate a new PKCS#12 file

This creates a new key, a certificate for the key and combines them in a PKCS#12 file in the parent directory. From this directory:

```bash
## generate private key
openssl genrsa -out certs/sample.key.pem 4096

## generate certificate signing request
openssl req -new -key certs/sample.key.pem -out certs/sample.csr

## generate and sign the certificate using rootca certificate
openssl ca -config openssl.cnf -notext -batch -in certs/sample.csr -out certs/sample.crt -extfile ext_template.cnf

## generate pkcs#12 file from key and certificate
openssl pkcs12 -export -out ../sample.p12 -inkey certs/sample.key.pem -in certs/sample.crt -certfile cacert.pem
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
