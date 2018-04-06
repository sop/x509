<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use X501\ASN1\Name;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;
use X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * Covers case when certification path length exceeds.
 *
 * @group certification-path
 */
class PathLengthFailValidationIntegrationTest extends \PHPUnit\Framework\TestCase
{
    const CA_NAME = "cn=CA";
    
    const INTERM_NAME = "cn=Interm";
    
    const CERT_NAME = "cn=EE";
    
    private static $_caKey;
    
    private static $_ca;
    
    private static $_intermKey;
    
    private static $_interm;
    
    private static $_certKey;
    
    private static $_cert;
    
    public static function setUpBeforeClass()
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-ca-rsa.pem"))->privateKeyInfo();
        self::$_intermKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-interm-rsa.pem"))->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-rsa.pem"))->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, "now + 1 hour"));
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true, 0));
        self::$_ca = $tbs->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_caKey);
        // create intermediate certificate
        $tbs = new TBSCertificate(Name::fromString(self::INTERM_NAME),
            self::$_intermKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, "now + 1 hour"));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true));
        self::$_interm = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::INTERM_NAME),
            Validity::fromStrings(null, "now + 1 hour"));
        $tbs = $tbs->withIssuerCertificate(self::$_interm);
        self::$_cert = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_intermKey);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_intermKey = null;
        self::$_interm = null;
        self::$_certKey = null;
        self::$_cert = null;
    }
    
    /* @formatter:off */
    /**
     * @expectedException X509\CertificationPath\Exception\PathValidationException
     */
    /* @formatter:on */
    public function testValidate()
    {
        $path = new CertificationPath(self::$_ca, self::$_interm, self::$_cert);
        $result = $path->validate(
            new PathValidationConfig(new DateTimeImmutable(), 3));
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }
}
