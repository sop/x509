<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\AttributeCertificate\AttCertValidityPeriod;
use Sop\X509\AttributeCertificate\AttributeCertificateInfo;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\Validation\ACValidationConfig;
use Sop\X509\AttributeCertificate\Validation\ACValidator;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateBundle;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\Certificate\Extension\TargetInformationExtension;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\Exception\X509ValidationException;
use Sop\X509\GeneralName\DNSName;

/**
 * @group ac-validation
 *
 * @internal
 */
class TargetMismatchACValidationIntegrationTest extends TestCase
{
    private static $_holderPath;

    private static $_issuerPath;

    private static $_ac;

    public static function setUpBeforeClass(): void
    {
        $root_ca = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $interms = CertificateBundle::fromPEMBundle(
            PEMBundle::fromFile(
                TEST_ASSETS_DIR . '/certs/intermediate-bundle.pem'));
        $holder = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $issuer = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $issuer_pk = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'));
        self::$_holderPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $holder, $interms);
        self::$_issuerPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $issuer, $interms);
        $aci = new AttributeCertificateInfo(Holder::fromPKC($holder),
            AttCertIssuer::fromPKC($issuer),
            AttCertValidityPeriod::fromStrings('now', 'now + 1 hour'),
            new Attributes());
        $aci = $aci->withAdditionalExtensions(
            TargetInformationExtension::fromTargets(
                new TargetName(new DNSName('test'))));
        self::$_ac = $aci->sign(new ECDSAWithSHA256AlgorithmIdentifier(),
            $issuer_pk);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_holderPath = null;
        self::$_issuerPath = null;
        self::$_ac = null;
    }

    public function testValidate()
    {
        $config = new ACValidationConfig(self::$_holderPath, self::$_issuerPath);
        $config = $config->withTargets(new TargetName(new DNSName('nope')));
        $validator = new ACValidator(self::$_ac, $config);
        $this->expectException(X509ValidationException::class);
        $validator->validate();
    }
}
