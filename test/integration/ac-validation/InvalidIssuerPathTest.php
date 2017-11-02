<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use X509\AttributeCertificate\AttCertIssuer;
use X509\AttributeCertificate\AttCertValidityPeriod;
use X509\AttributeCertificate\AttributeCertificateInfo;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Holder;
use X509\AttributeCertificate\Validation\ACValidationConfig;
use X509\AttributeCertificate\Validation\ACValidator;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\CertificationPath\CertificationPath;

/**
 * @group ac-validation
 */
class InvalidIssuerACValidationIntegrationTest extends PHPUnit_Framework_TestCase
{
    private static $_holderPath;
    
    private static $_issuerPath;
    
    private static $_ac;
    
    public static function setUpBeforeClass()
    {
        $root_ca = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
        $interms = CertificateBundle::fromPEMBundle(
            PEMBundle::fromFile(
                TEST_ASSETS_DIR . "/certs/intermediate-bundle.pem"));
        $holder = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem"));
        $issuer = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ecdsa.pem"));
        $issuer_pk = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-ec.pem"));
        self::$_holderPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $holder, $interms);
        // intentionally missing intermediate certificate
        self::$_issuerPath = new CertificationPath($root_ca, $issuer);
        $aci = new AttributeCertificateInfo(Holder::fromPKC($holder),
            AttCertIssuer::fromPKC($issuer),
            AttCertValidityPeriod::fromStrings("now", "now + 1 hour"),
            new Attributes());
        self::$_ac = $aci->sign(new ECDSAWithSHA256AlgorithmIdentifier(),
            $issuer_pk);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_holderPath = null;
        self::$_issuerPath = null;
        self::$_ac = null;
    }
    
    /**
     * @expectedException X509\Exception\X509ValidationException
     */
    public function testValidate()
    {
        $config = new ACValidationConfig(self::$_holderPath, self::$_issuerPath);
        $validator = new ACValidator(self::$_ac, $config);
        $validator->validate();
    }
}
