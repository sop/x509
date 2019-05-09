<?php
/**
 * Create attribute certificate.
 *
 * php ac-example.php
 */

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SignatureAlgorithmIdentifierFactory;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\Name;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\AttributeCertificate\AttCertValidityPeriod;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\AttributeCertificateInfo;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\AttributeCertificate\Validation\ACValidationConfig;
use Sop\X509\AttributeCertificate\Validation\ACValidator;
use Sop\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\Certificate\Extension\TargetInformationExtension;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

require dirname(__DIR__) . '/vendor/autoload.php';

// CA private key
openssl_pkey_export(
    openssl_pkey_new(
        ['private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048, ]), $pkey);
$ca_private_key = PrivateKeyInfo::fromPEM(PEM::fromString($pkey));
// Issuer private key
openssl_pkey_export(
    openssl_pkey_new(
        ['private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048, ]), $pkey);
$issuer_private_key = PrivateKeyInfo::fromPEM(PEM::fromString($pkey));
// Holder private key
openssl_pkey_export(
    openssl_pkey_new(
        ['private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048, ]), $pkey);
$holder_private_key = PrivateKeyInfo::fromPEM(PEM::fromString($pkey));

// create trust anchor certificate (self signed)
$tbs_cert = new TBSCertificate(
    Name::fromString('cn=CA'),
    $ca_private_key->publicKeyInfo(),
    Name::fromString('cn=CA'),
    Validity::fromStrings('now', 'now + 1 year'));
$tbs_cert = $tbs_cert->withRandomSerialNumber()
    ->withAdditionalExtensions(
        new BasicConstraintsExtension(true, true),
        new SubjectKeyIdentifierExtension(false,
            $ca_private_key->publicKeyInfo()->keyIdentifier()),
        new KeyUsageExtension(true,
            KeyUsageExtension::DIGITAL_SIGNATURE |
            KeyUsageExtension::KEY_CERT_SIGN));
$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
    $ca_private_key->algorithmIdentifier(),
    new SHA256AlgorithmIdentifier());
$ca_cert = $tbs_cert->sign($algo, $ca_private_key);

// create AC issuer certificate
$tbs_cert = new TBSCertificate(
    Name::fromString('cn=Issuer'),
    $issuer_private_key->publicKeyInfo(),
    new Name(),
    Validity::fromStrings('now', 'now + 6 months'));
$tbs_cert = $tbs_cert->withIssuerCertificate($ca_cert)
    ->withRandomSerialNumber()
    ->withAdditionalExtensions(
        // issuer must not be a CA
        new BasicConstraintsExtension(true, false),
        new KeyUsageExtension(true,
            KeyUsageExtension::DIGITAL_SIGNATURE |
             KeyUsageExtension::KEY_ENCIPHERMENT));
$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
    $ca_private_key->algorithmIdentifier(),
    new SHA256AlgorithmIdentifier());
$issuer_cert = $tbs_cert->sign($algo, $ca_private_key);

// create AC holder certificate
$tbs_cert = new TBSCertificate(
    Name::fromString('cn=Holder, gn=John, sn=Doe'),
    $holder_private_key->publicKeyInfo(),
    new Name(),
    Validity::fromStrings('now', 'now + 6 months'));
$tbs_cert = $tbs_cert->withIssuerCertificate($ca_cert)
    ->withRandomSerialNumber()
    ->withAdditionalExtensions(
        new BasicConstraintsExtension(true, false),
        new KeyUsageExtension(true,
            KeyUsageExtension::DIGITAL_SIGNATURE |
             KeyUsageExtension::KEY_ENCIPHERMENT));
$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
    $ca_private_key->algorithmIdentifier(),
    new SHA256AlgorithmIdentifier());
$holder_cert = $tbs_cert->sign($algo, $ca_private_key);

// named authority that grants the attributes
$authority = new GeneralNames(
    new UniformResourceIdentifier('uri:trusted_authority'));
// role attribute
$attribs = new Attributes(
    Attribute::fromAttributeValues(
        RoleAttributeValue::fromString('role-name', $authority)));
$aci = new AttributeCertificateInfo(
    // holder is identified by the holder's public key certificate
    new Holder(IssuerSerial::fromPKC($holder_cert)),
    AttCertIssuer::fromPKC($issuer_cert),
    AttCertValidityPeriod::fromStrings('now - 1 hour', 'now + 3 months'),
    $attribs);
$aci = $aci->withRandomSerialNumber()
    ->withAdditionalExtensions(
        // named target identifier
        TargetInformationExtension::fromTargets(
            new TargetName(
                new UniformResourceIdentifier('uri:target_identifier'))),
        // key identifier of the AC issuer
        new AuthorityKeyIdentifierExtension(false,
            $issuer_cert->tbsCertificate()
                ->subjectPublicKeyInfo()
                ->keyIdentifier()));
$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
    $issuer_private_key->algorithmIdentifier(),
    new SHA256AlgorithmIdentifier());
$ac = $aci->sign($algo, $issuer_private_key);

// validate AC
$holder_path = new CertificationPath($ca_cert, $holder_cert);
$issuer_path = new CertificationPath($ca_cert, $issuer_cert);
$validator_config = new ACValidationConfig($holder_path, $issuer_path);
// targetting must match
$target = new TargetName(new UniformResourceIdentifier('uri:target_identifier'));
$validator_config = $validator_config->withTargets($target);
$validator = new ACValidator($ac, $validator_config);
if ($validator->validate()) {
    fprintf(STDERR, "AC validation succeeded.\n");
}

fprintf(STDERR, "Root certificate:\n");
echo "{$ca_cert}\n";
fprintf(STDERR, "Issuer certificate:\n");
echo "{$issuer_cert}\n";
fprintf(STDERR, "Holder certificate:\n");
echo "{$holder_cert}\n";
fprintf(STDERR, "Attribute certificate:\n");
echo "{$ac}\n";
