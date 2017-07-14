# RSA Keys for Unit Tests

Below are the commands used to generate public and private RSA keys
for unit testing.

## Generate RSA keys

    openssl genpkey -out private_key.pem -algorithm RSA &&
    openssl rsa -in private_key.pem -pubout -out public_key.pem
