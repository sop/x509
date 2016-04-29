<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\Crypto\Signature;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\CertificationRequest\CertificationRequest;
use X509\CertificationRequest\CertificationRequestInfo;


/**
 * @group csr
 */
class CertificationRequestTest extends PHPUnit_Framework_TestCase
{
	private static $_subject;
	
	private static $_privateKeyInfo;
	
	public static function setUpBeforeClass() {
		self::$_subject = Name::fromString("cn=Subject");
		self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_subject = null;
		self::$_privateKeyInfo = null;
	}
	
	public function testCreate() {
		$pkinfo = self::$_privateKeyInfo->privateKey()
			->publicKey()
			->publicKeyInfo();
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
	 *
	 * @param CertificationRequest $cr
	 */
	public function testEncode(CertificationRequest $cr) {
		$seq = $cr->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$cr = CertificationRequest::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(CertificationRequest::class, $cr);
		return $cr;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param CertificationRequest $ref
	 * @param CertificationRequest $new
	 */
	public function testRecoded(CertificationRequest $ref, 
			CertificationRequest $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationRequest $cr
	 */
	public function testCertificationRequestInfo(CertificationRequest $cr) {
		$this->assertInstanceOf(CertificationRequestInfo::class, 
			$cr->certificationRequestInfo());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationRequest $cr
	 */
	public function testAlgo(CertificationRequest $cr) {
		$this->assertInstanceOf(
			SHA256WithRSAEncryptionAlgorithmIdentifier::class, 
			$cr->signatureAlgorithm());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationRequest $cr
	 */
	public function testSignature(CertificationRequest $cr) {
		$this->assertInstanceOf(Signature::class, $cr->signature());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationRequest $cr
	 */
	public function testVerify(CertificationRequest $cr) {
		$this->assertTrue($cr->verify(Crypto::getDefault()));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationRequest $cr
	 */
	public function testToPEM(CertificationRequest $cr) {
		$pem = $cr->toPEM();
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testToPEM
	 *
	 * @param PEM $pem
	 */
	public function testPEMType(PEM $pem) {
		$this->assertEquals(PEM::TYPE_CERTIFICATE_REQUEST, $pem->type());
	}
	
	/**
	 * @depends testToPEM
	 *
	 * @param PEM $pem
	 */
	public function testFromPEM(PEM $pem) {
		$cr = CertificationRequest::fromPEM($pem);
		$this->assertInstanceOf(CertificationRequest::class, $cr);
		return $cr;
	}
	
	/**
	 * @depends testCreate
	 * @depends testFromPEM
	 *
	 * @param CertificationRequest $ref
	 * @param CertificationRequest $new
	 */
	public function testPEMRecoded(CertificationRequest $ref, 
			CertificationRequest $new) {
		$this->assertEquals($ref, $new);
	}
}
