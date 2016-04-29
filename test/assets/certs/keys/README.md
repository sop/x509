# Keys for Certificate Signing
Below are the commands used to generate keys for test certificates.

## RSA
Generate RSA keys.

    openssl genrsa -out acme-ca-rsa.pem 4096 &&
    openssl genrsa -out acme-interm-rsa.pem 2048 &&
    openssl genrsa -out acme-rsa.pem 1024

## Elliptic Curve
Generate elliptic curve keys.

    openssl genpkey -out acme-interm-ec.pem -algorithm EC \
      -pkeyopt ec_paramgen_curve:prime256v1 \
      -pkeyopt ec_param_enc:named_curve &&
    openssl genpkey -out acme-ec.pem -algorithm EC \
      -pkeyopt ec_paramgen_curve:prime256v1 \
      -pkeyopt ec_param_enc:named_curve
