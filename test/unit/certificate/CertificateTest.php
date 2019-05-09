<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;

/**
 * @group certificate
 *
 * @internal
 */
class CertificateTest extends TestCase
{
    private static $_privateKeyInfo;

    public static function setUpBeforeClass(): void
    {
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privateKeyInfo = null;
    }

    public function testCreate()
    {
        $pki = self::$_privateKeyInfo->publicKeyInfo();
        $tc = new TBSCertificate(Name::fromString('cn=Subject'), $pki,
            Name::fromString('cn=Issuer'), Validity::fromStrings(null, null));
        $tc = $tc->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(0)
            ->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $signature = Crypto::getDefault()->sign(
            $tc->toASN1()
                ->toDER(), self::$_privateKeyInfo, $tc->signature());
        $cert = new Certificate($tc, $tc->signature(), $signature);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testEncode(Certificate $cert)
    {
        $seq = $cert->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $cert = Certificate::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Certificate $ref
     * @param Certificate $new
     */
    public function testRecoded(Certificate $ref, Certificate $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testTBSCertificate(Certificate $cert)
    {
        $this->assertInstanceOf(TBSCertificate::class, $cert->tbsCertificate());
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testSignatureAlgorithm(Certificate $cert)
    {
        $this->assertInstanceOf(AlgorithmIdentifier::class,
            $cert->signatureAlgorithm());
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testSignature(Certificate $cert)
    {
        $this->assertInstanceOf(Signature::class, $cert->signatureValue());
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testToPEM(Certificate $cert)
    {
        $pem = $cert->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testPEMType(PEM $pem)
    {
        $this->assertEquals(PEM::TYPE_CERTIFICATE, $pem->type());
    }

    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testFromPEM(PEM $pem)
    {
        $cert = Certificate::fromPEM($pem);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends testCreate
     * @depends testFromPEM
     *
     * @param Certificate $ref
     * @param Certificate $new
     */
    public function testPEMRecoded(Certificate $ref, Certificate $new)
    {
        $this->assertEquals($ref, $new);
    }

    public function testFromInvalidPEMFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        Certificate::fromPEM(new PEM('nope', ''));
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testToString(Certificate $cert)
    {
        $this->assertIsString(strval($cert));
    }

    /**
     * @depends testCreate
     *
     * @param Certificate $cert
     */
    public function testInvalidAlgoFail(Certificate $cert)
    {
        $seq = $cert->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(\UnexpectedValueException::class);
        Certificate::fromASN1($seq);
    }
}
