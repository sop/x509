# Certificates for Unit Tests
Below are the commands used to generate certificates for unit testing.

## Generate CA Certificate
Create CA certificate `acme-ca.pem` with RSA encryption.

    openssl req -new -x509 -key keys/acme-ca-rsa.pem \
      -config conf/acme-ca.cnf -batch -days 3650 \
      -subj "/CN=ACME Root CA/C=FI/O=ACME Ltd." \
      -set_serial 1 -out acme-ca.pem

## Generate Intermediate Certificate with RSA
Create intermediate certificate `acme-interm-rsa.pem` with RSA encryption.

    mkdir -p db && echo -n > db/ca.db &&
    echo 01 > db/serial.txt &&
    openssl req -new -config conf/acme-interm-rsa.cnf -batch \
      -key keys/acme-interm-rsa.pem \
      -subj "/CN=ACME Intermediate CA/C=FI/O=ACME Ltd." \
      -out acme-interm-rsa.csr &&
    openssl ca -config conf/acme-interm-rsa.cnf -batch \
      -cert acme-ca.pem -keyfile keys/acme-ca-rsa.pem \
      -startdate 160101120000Z -enddate 260102150405Z \
      -preserveDN -outdir db -notext \
      -in acme-interm-rsa.csr -out acme-interm-rsa.pem

## Generate ACME Certificate
Create `acme-rsa.pem` certificate for testing.
Store certificate signature to `acme-rsa.pem.sig` and
CSR signature to `acme-rsa.csr.sig`.

    mkdir -p db && echo -n > db/ca.db &&
    echo 2A > db/serial.txt &&
    openssl req -new -config conf/acme-rsa.cnf -batch \
      -key keys/acme-rsa.pem \
      -subj "/CN=example.com/C=FI/O=ACME Ltd." \
      -out acme-rsa.csr &&
    openssl ca -config conf/acme-rsa.cnf -batch \
      -cert acme-interm-rsa.pem \
      -keyfile keys/acme-interm-rsa.pem \
      -startdate 160101120000Z -enddate 260102150405Z \
      -preserveDN -outdir db -notext \
      -in acme-rsa.csr -out acme-rsa.pem

## Generate Intermediate Certificate with ECDSA
Create intermediate certificate `acme-interm-ecdsa.pem` with
elliptic curve encryption.

    mkdir -p db && echo -n > db/ca.db &&
    echo 0ECD5A > db/serial.txt &&
    openssl req -new -config conf/acme-interm-ecdsa.cnf -batch \
      -key keys/acme-interm-ec.pem \
      -subj "/CN=ACME Intermediate ECDSA CA/C=FI/O=ACME Ltd." \
      -out acme-interm-ecdsa.csr &&
    openssl ca -config conf/acme-interm-ecdsa.cnf -batch \
      -cert acme-ca.pem -keyfile keys/acme-ca-rsa.pem \
      -startdate 160101120000Z -enddate 260102150405Z \
      -preserveDN -outdir db -notext \
      -in acme-interm-ecdsa.csr -out acme-interm-ecdsa.pem

## Generate ACME Certificate with ECDSA
Create `acme-ecdsa.pem` certificate with elliptic curve encryption.

    mkdir -p db && echo -n > db/ca.db &&
    echo 1ECD5A > db/serial.txt &&
    openssl req -new -config conf/acme-ecdsa.cnf -batch \
      -key keys/acme-ec.pem \
      -subj "/CN=ACME ECDSA/C=FI/O=ACME Ltd." \
      -out acme-ecdsa.csr &&
    openssl ca -config conf/acme-ecdsa.cnf -batch \
      -cert acme-interm-ecdsa.pem \
      -keyfile keys/acme-interm-ec.pem \
      -startdate 160101120000Z -enddate 260102150405Z \
      -preserveDN -outdir db -notext \
      -in acme-ecdsa.csr -out acme-ecdsa.pem

# Extract Signatures
Extract signatures from certificates and certification requests.

    for f in acme-*.pem; do
      openssl x509 -noout -text -in "$f" |
        grep -Pzo '(\s*[0-9a-f]{2}:)*[0-9a-f]{2}\s*\Z' |
        paste -s -d ' ' | tr -d ' :' > "$f.sig"
    done &&
    for f in acme-*.csr; do
      openssl req -noout -text -in "$f" |
        grep -Pzo '(\s*[0-9a-f]{2}:)*[0-9a-f]{2}\s*\Z' |
        paste -s -d ' ' | tr -d ' :' | tr -d ' :' > "$f.sig"
    done

# Combine to Bundle
Combine intermediate certificates to bundle.

    cat acme-interm-*.pem > intermediate-bundle.pem
