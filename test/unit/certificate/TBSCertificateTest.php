<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;


/**
 * @group certificate
 */
class TBSCertificateTest extends PHPUnit_Framework_TestCase
{
	private static $_subject;
	
	private static $_privateKeyInfo;
	
	private static $_issuer;
	
	private static $_validity;
	
	public static function setUpBeforeClass() {
		self::$_subject = Name::fromString("cn=Subject");
		self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		self::$_issuer = Name::fromString("cn=Issuer");
		self::$_validity = Validity::fromStrings("2016-04-26 12:00:00", 
			"2016-04-26 13:00:00");
	}
	
	public static function tearDownAfterClass() {
		self::$_subject = null;
		self::$_privateKeyInfo = null;
		self::$_issuer = null;
		self::$_validity = null;
	}
	
	public function testCreate() {
		$tc = new TBSCertificate(self::$_subject, 
			self::$_privateKeyInfo->privateKey()
				->publicKey()
				->publicKeyInfo(), self::$_issuer, self::$_validity);
		$tc = $tc->withVersion(TBSCertificate::VERSION_1)
			->withSerialNumber(0)
			->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier());
		$this->assertInstanceOf(TBSCertificate::class, $tc);
		return $tc;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testEncode(TBSCertificate $tc) {
		$seq = $tc->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$tc = TBSCertificate::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(TBSCertificate::class, $tc);
		return $tc;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param TBSCertificate $ref
	 * @param TBSCertificate $new
	 */
	public function testRecoded(TBSCertificate $ref, TBSCertificate $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testVersion(TBSCertificate $tc) {
		$this->assertEquals(TBSCertificate::VERSION_1, $tc->version());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSerialNumber(TBSCertificate $tc) {
		$this->assertEquals(0, $tc->serialNumber());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSignature(TBSCertificate $tc) {
		$this->assertEquals(new SHA1WithRSAEncryptionAlgorithmIdentifier(), 
			$tc->signature());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testIssuer(TBSCertificate $tc) {
		$this->assertEquals(self::$_issuer, $tc->issuer());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testValidity(TBSCertificate $tc) {
		$this->assertEquals(self::$_validity, $tc->validity());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSubject(TBSCertificate $tc) {
		$this->assertEquals(self::$_subject, $tc->subject());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSubjectPKI(TBSCertificate $tc) {
		$this->assertEquals(
			self::$_privateKeyInfo->privateKey()
				->publicKey()
				->publicKeyInfo(), $tc->subjectPublicKeyInfo());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testHasNoExtensions(TBSCertificate $tc) {
		$this->assertCount(0, $tc->extensions());
	}
}
