<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\CertificationRequest\CertificationRequest;
use Sop\X509\CertificationRequest\CertificationRequestInfo;

/**
 * @group csr
 *
 * @internal
 */
class CertificationRequestTest extends TestCase
{
    private static $_subject;

    private static $_privateKeyInfo;

    public static function setUpBeforeClass(): void
    {
        self::$_subject = Name::fromString('cn=Subject');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_subject = null;
        self::$_privateKeyInfo = null;
    }

    public function testCreate()
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        $cri = new CertificationRequestInfo(self::$_subject, $pkinfo);
        $data = $cri->toASN1()->toDER();
        $algo = new SHA256WithRSAEncryptionAlgorithmIdentifier();
        $signature = Crypto::getDefault()->sign($data, self::$_privateKeyInfo,
            $algo);
        $cr = new CertificationRequest($cri, $algo, $signature);
        $this->assertInstanceOf(CertificationRequest::class, $cr);
        return $cr;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(CertificationRequest $cr)
    {
        $seq = $cr->toASN1();
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
        $cr = CertificationRequest::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(CertificationRequest::class, $cr);
        return $cr;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(CertificationRequest $ref,
        CertificationRequest $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testCertificationRequestInfo(CertificationRequest $cr)
    {
        $this->assertInstanceOf(CertificationRequestInfo::class,
            $cr->certificationRequestInfo());
    }

    /**
     * @depends testCreate
     */
    public function testAlgo(CertificationRequest $cr)
    {
        $this->assertInstanceOf(
            SHA256WithRSAEncryptionAlgorithmIdentifier::class,
            $cr->signatureAlgorithm());
    }

    /**
     * @depends testCreate
     */
    public function testSignature(CertificationRequest $cr)
    {
        $this->assertInstanceOf(Signature::class, $cr->signature());
    }

    /**
     * @depends testCreate
     */
    public function testVerify(CertificationRequest $cr)
    {
        $this->assertTrue($cr->verify());
    }

    /**
     * @depends testCreate
     */
    public function testInvalidAlgoFail(CertificationRequest $cr)
    {
        $seq = $cr->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        CertificationRequest::fromASN1($seq);
    }

    /**
     * @depends testCreate
     */
    public function testToPEM(CertificationRequest $cr)
    {
        $pem = $cr->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testCreate
     */
    public function testToString(CertificationRequest $cr)
    {
        $this->assertIsString(strval($cr));
    }

    /**
     * @depends testToPEM
     */
    public function testPEMType(PEM $pem)
    {
        $this->assertEquals(PEM::TYPE_CERTIFICATE_REQUEST, $pem->type());
    }

    /**
     * @depends testToPEM
     */
    public function testFromPEM(PEM $pem)
    {
        $cr = CertificationRequest::fromPEM($pem);
        $this->assertInstanceOf(CertificationRequest::class, $cr);
        return $cr;
    }

    /**
     * @depends testCreate
     * @depends testFromPEM
     */
    public function testPEMRecoded(CertificationRequest $ref,
        CertificationRequest $new)
    {
        $this->assertEquals($ref, $new);
    }

    public function testFromInvalidPEMFail()
    {
        $this->expectException(UnexpectedValueException::class);
        CertificationRequest::fromPEM(new PEM('nope', ''));
    }
}
