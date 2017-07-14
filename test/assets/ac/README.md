# Attribute Certificate for Unit Tests

In lack of 3rd party AC tools, reference attribute certificates are generated
using this library.

strongSwan invocation instructions are left here for future reference.

## Generate AC

    php make-ac.php > acme-ac.pem

## strongSwan

Attribute Certificate (AC) may be generated using
[strongSwan](https://wiki.strongswan.org/projects/strongswan)'s
[ipsec pki --acert](https://wiki.strongswan.org/projects/strongswan/wiki/IpsecPkiAcert)
tool.

**NOTE**: Current implementation (5.4.0) appears to be broken such that
Authority Key Identifier extension is encoded incorrectly.

    ipsec pki --acert --in acme-rsa.pem \
      --issuercert acme-interm-rsa.pem \
      --issuerkey keys/acme-interm-rsa.pem \
      --dateform "%Y-%m-%d %H:%M:%S" \
      --not-before "2016-01-01 12:00:00" \
      --not-after "2017-01-01 12:00:00" \
      --group "group1" --group "group2" \
      --serial 1 --outform pem > acme-ac.pem
