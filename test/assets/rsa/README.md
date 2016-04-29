# RSA Keys for Unit Tests
Below are the commands used to generate public and private RSA keys
for unit testing.

## Generate RSA keys
    openssl genrsa -out rsa_private_key.pem &&
    openssl pkey -in rsa_private_key.pem -out private_key.pem &&
    openssl rsa -in private_key.pem -RSAPublicKey_out -out rsa_public_key.pem &&
    openssl rsa -in private_key.pem -pubout -out public_key.pem

## Generate Encrypted Keys
    openssl pkcs8 -in private_key.pem -topk8 \
      -v1 PBE-SHA1-RC2-64 -passout pass:password \
      -out encrypted_private_key.pem &&
    openssl pkcs8 -in private_key.pem -topk8 \
      -v2 des3 -passout pass:password \
      -out encrypted_private_key_v2.pem
