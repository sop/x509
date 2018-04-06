<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use X501\ASN1\Name;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\Certificate\Extension\CertificatePoliciesExtension;
use X509\Certificate\Extension\PolicyMappingsExtension;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Covers validation failure when anyPolicy appears in policy mapping.
 *
 * @group certification-path
 */
class PolicyMappingAnyPolicyValidationIntegrationTest extends \PHPUnit\Framework\TestCase
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
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true, 1),
            new CertificatePoliciesExtension(false,
                new PolicyInformation("1.3.6.1.3.1")),
            new PolicyMappingsExtension(true,
                new PolicyMapping("1.3.6.1.3.1",
                    PolicyInformation::OID_ANY_POLICY)));
        self::$_ca = $tbs->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, "now + 1 hour"));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new CertificatePoliciesExtension(false,
                new PolicyInformation("1.3.6.1.3.2")));
        self::$_cert = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
    }
    
    public static function tearDownAfterClass()
    {
        self::$_caKey = null;
        self::$_ca = null;
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
        $path = new CertificationPath(self::$_ca, self::$_cert);
        $config = new PathValidationConfig(new DateTimeImmutable(), 3);
        $config = $config->withExplicitPolicy(true);
        $path->validate($config);
    }
}
