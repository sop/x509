<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\NullType;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\Certificate\Certificate;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\Certificate\Extension\UnknownExtension;
use X509\Certificate\Extensions;
use X509\Certificate\TBSCertificate;
use X509\Certificate\UniqueIdentifier;
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
			self::$_privateKeyInfo->publicKeyInfo(), self::$_issuer, 
			self::$_validity);
		$this->assertInstanceOf(TBSCertificate::class, $tc);
		return $tc;
	}
	
	public function testCreateWithAll() {
		$tc = new TBSCertificate(self::$_subject, 
			self::$_privateKeyInfo->publicKeyInfo(), self::$_issuer, 
			self::$_validity);
		$tc = $tc->withVersion(TBSCertificate::VERSION_3)
			->withSerialNumber(1)
			->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier())
			->withIssuerUniqueID(UniqueIdentifier::fromString("issuer"))
			->withSubjectUniqueID(UniqueIdentifier::fromString("subject"))
			->withAdditionalExtensions(
			new BasicConstraintsExtension(true, false));
		$this->assertInstanceOf(TBSCertificate::class, $tc);
		return $tc;
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testEncodeWithAll(TBSCertificate $tc) {
		$seq = $tc->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncodeWithAll
	 *
	 * @param string $der
	 */
	public function testDecodeWithAll($der) {
		$tc = TBSCertificate::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(TBSCertificate::class, $tc);
		return $tc;
	}
	
	/**
	 * @depends testCreateWithAll
	 * @depends testDecodeWithAll
	 *
	 * @param TBSCertificate $ref
	 * @param TBSCertificate $new
	 */
	public function testRecoded(TBSCertificate $ref, TBSCertificate $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testVersion(TBSCertificate $tc) {
		$this->assertEquals(TBSCertificate::VERSION_3, $tc->version());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSerialNumber(TBSCertificate $tc) {
		$this->assertEquals(1, $tc->serialNumber());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSignature(TBSCertificate $tc) {
		$this->assertEquals(new SHA1WithRSAEncryptionAlgorithmIdentifier(), 
			$tc->signature());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testIssuer(TBSCertificate $tc) {
		$this->assertEquals(self::$_issuer, $tc->issuer());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testValidity(TBSCertificate $tc) {
		$this->assertEquals(self::$_validity, $tc->validity());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSubject(TBSCertificate $tc) {
		$this->assertEquals(self::$_subject, $tc->subject());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSubjectPKI(TBSCertificate $tc) {
		$this->assertEquals(self::$_privateKeyInfo->publicKeyInfo(), 
			$tc->subjectPublicKeyInfo());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testIssuerUniqueID(TBSCertificate $tc) {
		$this->assertEquals("issuer", $tc->issuerUniqueID()
			->string());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSubjectUniqueID(TBSCertificate $tc) {
		$this->assertEquals("subject", $tc->subjectUniqueID()
			->string());
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param TBSCertificate $tc
	 */
	public function testExtensions(TBSCertificate $tc) {
		$this->assertInstanceOf(Extensions::class, $tc->extensions());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithVersion(TBSCertificate $tc) {
		$tc = $tc->withVersion(TBSCertificate::VERSION_1);
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithSerialNumber(TBSCertificate $tc) {
		$tc = $tc->withSerialNumber(123);
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithRandomSerialNumber(TBSCertificate $tc) {
		$tc = $tc->withRandomSerialNumber(16);
		$bin = gmp_export(gmp_init($tc->serialNumber(), 10), 1);
		$this->assertEquals(16, strlen($bin));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithSignature(TBSCertificate $tc) {
		$tc = $tc->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier());
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithIssuer(TBSCertificate $tc) {
		$tc = $tc->withIssuer(self::$_issuer);
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithValidity(TBSCertificate $tc) {
		$tc = $tc->withValidity(self::$_validity);
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithSubject(TBSCertificate $tc) {
		$tc = $tc->withSubject(self::$_subject);
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithSubjectPublicKeyInfo(TBSCertificate $tc) {
		$tc = $tc->withSubjectPublicKeyInfo(
			self::$_privateKeyInfo->publicKeyInfo());
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithIssuerUniqueID(TBSCertificate $tc) {
		$tc = $tc->withIssuerUniqueID(UniqueIdentifier::fromString("uid"));
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithSubjectUniqueID(TBSCertificate $tc) {
		$tc = $tc->withSubjectUniqueID(UniqueIdentifier::fromString("uid"));
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithExtensions(TBSCertificate $tc) {
		$tc = $tc->withExtensions(new Extensions());
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testWithAdditionalExtensions(TBSCertificate $tc) {
		$tc = $tc->withAdditionalExtensions(
			new UnknownExtension("1.3.6.1.3", false, new NullType()));
		$this->assertInstanceOf(TBSCertificate::class, $tc);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param TBSCertificate $tc
	 */
	public function testNoVersionFail(TBSCertificate $tc) {
		$tc->version();
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param TBSCertificate $tc
	 */
	public function testNoSerialFail(TBSCertificate $tc) {
		$tc->serialNumber();
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param TBSCertificate $tc
	 */
	public function testNoSignatureFail(TBSCertificate $tc) {
		$tc->signature();
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param TBSCertificate $tc
	 */
	public function testNoIssuerUniqueIDFail(TBSCertificate $tc) {
		$tc->issuerUniqueID();
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param TBSCertificate $tc
	 */
	public function testNoSubjectUniqueIDFail(TBSCertificate $tc) {
		$tc->subjectUniqueID();
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testSign(TBSCertificate $tc) {
		$cert = $tc->sign(Crypto::getDefault(), 
			new SHA1WithRSAEncryptionAlgorithmIdentifier(), 
			self::$_privateKeyInfo);
		$this->assertInstanceOf(Certificate::class, $cert);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param TBSCertificate $tc
	 */
	public function testDecodeVersion1(TBSCertificate $tc) {
		$tc = $tc->withVersion(TBSCertificate::VERSION_1)
			->withSerialNumber(1)
			->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier());
		$seq = $tc->toASN1();
		$tbs_cert = TBSCertificate::fromASN1($seq);
		$this->assertInstanceOf(TBSCertificate::class, $tbs_cert);
	}
}
