<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\CertificatePoliciesExtension;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\PolicyConstraintsExtension;
use Sop\X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use Sop\X509\Certificate\Extension\PolicyMappingsExtension;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\Exception\PathValidationException;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Covers policy mapping inhibit handling.
 *
 * @group certification-path
 *
 * @internal
 */
class PolicyMappingInhibitValidationIntegrationTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const INTERM_NAME = 'cn=Interm';

    public const CERT_NAME = 'cn=EE';

    private static $_caKey;

    private static $_ca;

    private static $_intermKey;

    private static $_interm;

    private static $_certKey;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))->privateKeyInfo();
        self::$_intermKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem'))->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true),
            new CertificatePoliciesExtension(false,
                new PolicyInformation('1.3.6.1.3.1')),
            new PolicyConstraintsExtension(true, 0, 0));
        self::$_ca = $tbs->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_caKey);
        // create intermediate certificate
        $tbs = new TBSCertificate(Name::fromString(self::INTERM_NAME),
            self::$_intermKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true),
            new CertificatePoliciesExtension(false,
                new PolicyInformation('1.3.6.1.3.1')),
            new PolicyMappingsExtension(true,
                new PolicyMapping('1.3.6.1.3.1', '1.3.6.1.3.2')));
        self::$_interm = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::INTERM_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate(self::$_interm);
        $tbs = $tbs->withAdditionalExtensions(
            new CertificatePoliciesExtension(false,
                new PolicyInformation('1.3.6.1.3.2')));
        self::$_cert = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_intermKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_intermKey = null;
        self::$_interm = null;
        self::$_certKey = null;
        self::$_cert = null;
    }

    public function testValidate()
    {
        $path = new CertificationPath(self::$_ca, self::$_interm, self::$_cert);
        $this->expectException(PathValidationException::class);
        $path->validate(new PathValidationConfig(new DateTimeImmutable(), 3));
    }
}
