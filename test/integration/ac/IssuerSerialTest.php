<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\UniqueIdentifier;
use Sop\X509\Certificate\Validity;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group ac
 *
 * @internal
 */
class IssuerSerialIntegrationTest extends TestCase
{
    private static $_cert;

    private static $_privKey;

    public static function setUpBeforeClass(): void
    {
        self::$_cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        self::$_privKey = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_cert = null;
        self::$_privKey = null;
    }

    public function testFromCertificate()
    {
        $is = IssuerSerial::fromPKC(self::$_cert);
        $this->assertInstanceOf(IssuerSerial::class, $is);
        return $is;
    }

    /**
     * @depends testFromCertificate
     */
    public function testIssuer(IssuerSerial $is)
    {
        $this->assertEquals(
            self::$_cert->tbsCertificate()
                ->issuer(), $is->issuer()
                ->firstDN());
    }

    /**
     * @depends testFromCertificate
     */
    public function testSerial(IssuerSerial $is)
    {
        $this->assertEquals(
            self::$_cert->tbsCertificate()
                ->serialNumber(), $is->serial());
    }

    public function testIdentifiesPKCSerialMismatch()
    {
        $is = new IssuerSerial(
            new GeneralNames(
                new DirectoryName(self::$_cert->tbsCertificate()->issuer())), 1);
        $this->assertFalse($is->identifiesPKC(self::$_cert));
    }

    public function testIdentifiesPKCWithIssuerUID()
    {
        $tbs = new TBSCertificate(Name::fromString('cn=Sub'),
            self::$_privKey->publicKeyInfo(), Name::fromString('cn=Iss'),
            Validity::fromStrings('now', 'now + 1 hour'));
        $tbs = $tbs->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        $cert = $tbs->sign(new SHA256WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privKey);
        $is = IssuerSerial::fromPKC($cert);
        $this->assertTrue($is->identifiesPKC($cert));
    }

    public function testIdentifiesPKCIssuerUIDMismatch()
    {
        $issuer = Name::fromString('cn=Iss');
        $tbs = new TBSCertificate(Name::fromString('cn=Sub'),
            self::$_privKey->publicKeyInfo(), $issuer,
            Validity::fromStrings('now', 'now + 1 hour'));
        $tbs = $tbs->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        $cert = $tbs->sign(new SHA256WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privKey);
        $is = new IssuerSerial(new GeneralNames(new DirectoryName($issuer)),
            $cert->tbsCertificate()->serialNumber(),
            UniqueIdentifier::fromString('fail'));
        $this->assertFalse($is->identifiesPKC($cert));
    }

    public function testIdentifiesPKCNoUID()
    {
        $is = new IssuerSerial(
            new GeneralNames(
                new DirectoryName(self::$_cert->tbsCertificate()->issuer())),
            self::$_cert->tbsCertificate()->serialNumber(),
            UniqueIdentifier::fromString('uid'));
        $this->assertFalse($is->identifiesPKC(self::$_cert));
    }
}
