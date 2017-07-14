<?php
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use X501\ASN1\Name;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;
use X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * Covers case when public key algorithm and parameters change.
 *
 * @group certification-path
 */
class DifferentAlgoParamsValidationIntegrationTest extends PHPUnit_Framework_TestCase
{
    const CA_NAME = "cn=CA";
    
    const CERT_NAME = "cn=EE";
    
    private static $_caKey;
    
    private static $_ca;
    
    private static $_certKey;
    
    private static $_cert;
    
    public static function setUpBeforeClass()
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-ca-rsa.pem"))->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-rsa.pem"))->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, "now + 1 hour"));
        self::$_ca = $tbs->sign(Crypto::getDefault(),
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
        // create end-entity certificate
        $pubkey = self::$_certKey->publicKeyInfo();
        // hack modified algorithm identifier into PublicKeyInfo
        $cls = new ReflectionClass($pubkey);
        $prop = $cls->getProperty("_algo");
        $prop->setAccessible(true);
        $prop->setValue($pubkey,
            new DifferentAlgoParamsValidationIntegrationTest_RSAAlgo());
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME), $pubkey,
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, "now + 1 hour"));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        self::$_cert = $tbs->sign(Crypto::getDefault(),
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_certKey = null;
        self::$_cert = null;
    }
    
    public function testValidate()
    {
        $path = new CertificationPath(self::$_ca, self::$_cert);
        $result = $path->validate(Crypto::getDefault(),
            new PathValidationConfig(new DateTimeImmutable(), 3));
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }
}

class DifferentAlgoParamsValidationIntegrationTest_RSAAlgo extends RSAEncryptionAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = "1.3.6.1.3";
    }
    
    protected function _paramsASN1()
    {
        return null;
    }
}
