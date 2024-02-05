<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\Certificate\Extension\NameConstraintsExtension;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;
use Sop\X509\GeneralName\DirectoryName;

/**
 * Covers handling of name constraints extension.
 *
 * @group certification-path
 *
 * @internal
 */
class NameConstraintsValidationIntegrationTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const CERT_NAME = 'cn=EE,c=FI';

    private static $_caKey;

    private static $_ca;

    private static $_certKey;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true, 1),
            new NameConstraintsExtension(true,
                new GeneralSubtrees(
                    new GeneralSubtree(DirectoryName::fromDNString('c=FI')))));
        self::$_ca = $tbs->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        self::$_cert = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_certKey = null;
        self::$_cert = null;
    }

    public function testValidate()
    {
        $path = new CertificationPath(self::$_ca, self::$_cert);
        $result = $path->validate(
            new PathValidationConfig(new DateTimeImmutable(), 3));
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }
}
