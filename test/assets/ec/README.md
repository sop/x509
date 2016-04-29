# Elliptic Curve Keys for Unit Tests
Below are the commands used to generate public and private elliptic curve keys
for unit testing.

## Generate keys
    openssl genpkey -out private_key.pem -algorithm EC \
      -pkeyopt ec_paramgen_curve:prime256v1 \
      -pkeyopt ec_param_enc:named_curve &&
    openssl ec -out public_key.pem \
      -in private_key.pem -pubout
