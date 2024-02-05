<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateBundle;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;

/**
 * @group certificate
 *
 * @internal
 */
class CertificateBundleTest extends TestCase
{
    private static $_pem1;

    private static $_cert1;

    private static $_pem2;

    private static $_cert2;

    private static $_pem3;

    private static $_cert3;

    public static function setUpBeforeClass(): void
    {
        self::$_pem1 = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem');
        self::$_cert1 = Certificate::fromPEM(self::$_pem1);
        self::$_pem2 = PEM::fromFile(
            TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem');
        self::$_cert2 = Certificate::fromPEM(self::$_pem2);
        self::$_pem3 = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        self::$_cert3 = Certificate::fromPEM(self::$_pem3);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pem1 = null;
        self::$_cert1 = null;
        self::$_pem2 = null;
        self::$_cert2 = null;
        self::$_pem3 = null;
        self::$_cert3 = null;
    }

    public function testCreate()
    {
        $bundle = new CertificateBundle(self::$_cert1, self::$_cert2);
        $this->assertInstanceOf(CertificateBundle::class, $bundle);
        return $bundle;
    }

    /**
     * @depends testCreate
     */
    public function testCount(CertificateBundle $bundle)
    {
        $this->assertCount(2, $bundle);
    }

    /**
     * @depends testCreate
     */
    public function testAll(CertificateBundle $bundle)
    {
        $this->assertCount(2, $bundle->all());
    }

    /**
     * @depends testCreate
     */
    public function testIterator(CertificateBundle $bundle)
    {
        $values = [];
        foreach ($bundle as $cert) {
            $values[] = $cert;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Certificate::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testContains(CertificateBundle $bundle)
    {
        $this->assertTrue($bundle->contains(self::$_cert1));
    }

    public function testDoesNotContain()
    {
        $bundle = new CertificateBundle(self::$_cert1, self::$_cert2);
        $this->assertFalse($bundle->contains(self::$_cert3));
    }

    public function testContainsSubjectMismatch()
    {
        $priv_key_info = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $tc = new TBSCertificate(Name::fromString('cn=Subject'),
            $priv_key_info->publicKeyInfo(), Name::fromString('cn=Issuer 1'),
            Validity::fromStrings(null, null));
        $cert1 = $tc->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            $priv_key_info);
        $tc = $tc->withSubject(Name::fromString('cn=Issuer 2'));
        $cert2 = $tc->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            $priv_key_info);
        $bundle = new CertificateBundle($cert1);
        $this->assertFalse($bundle->contains($cert2));
    }

    /**
     * @depends testCreate
     */
    public function testAllBySubjectKeyID(CertificateBundle $bundle)
    {
        $id = self::$_cert2->tbsCertificate()
            ->extensions()
            ->subjectKeyIdentifier()
            ->keyIdentifier();
        $certs = $bundle->allBySubjectKeyIdentifier($id);
        $this->assertCount(1, $certs);
    }

    /**
     * @depends testCreate
     */
    public function testWithPEM(CertificateBundle $bundle)
    {
        $bundle = $bundle->withPEM(self::$_pem3);
        $this->assertCount(3, $bundle);
    }

    /**
     * @depends testCreate
     */
    public function testWithPEMBundle(CertificateBundle $bundle)
    {
        $bundle = $bundle->withPEMBundle(new PEMBundle(self::$_pem3));
        $this->assertCount(3, $bundle);
    }

    /**
     * @depends testCreate
     */
    public function testWithCertificates(CertificateBundle $bundle)
    {
        $bundle = $bundle->withCertificates(Certificate::fromPEM(self::$_pem3));
        $this->assertCount(3, $bundle);
    }

    public function testFromPEMBundle()
    {
        $bundle = CertificateBundle::fromPEMBundle(
            new PEMBundle(self::$_pem1, self::$_pem2));
        $this->assertInstanceOf(CertificateBundle::class, $bundle);
    }

    public function testFromPEMs()
    {
        $bundle = CertificateBundle::fromPEMs(self::$_pem1, self::$_pem2);
        $this->assertInstanceOf(CertificateBundle::class, $bundle);
    }

    public function testSearchBySubjectKeyHavingNoID()
    {
        $priv_key_info = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $tc = new TBSCertificate(Name::fromString('cn=Subject'),
            $priv_key_info->publicKeyInfo(), Name::fromString('cn=Issuer'),
            Validity::fromStrings(null, null));
        $cert = $tc->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            $priv_key_info);
        $bundle = new CertificateBundle($cert);
        $this->assertEmpty($bundle->allBySubjectKeyIdentifier('nope'));
    }
}
