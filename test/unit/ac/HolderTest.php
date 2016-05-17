<?php

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use X509\AttributeCertificate\Holder;
use X509\AttributeCertificate\IssuerSerial;
use X509\AttributeCertificate\ObjectDigestInfo;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;


/**
 * @group ac
 */
class HolderTest extends PHPUnit_Framework_TestCase
{
	private static $_issuerSerial;
	
	private static $_subject;
	
	private static $_odi;
	
	public static function setUpBeforeClass() {
		self::$_issuerSerial = new IssuerSerial(
			new GeneralNames(DirectoryName::fromDNString("cn=Test")), 1);
		self::$_subject = new GeneralNames(
			DirectoryName::fromDNString("cn=Subject"));
		self::$_odi = new ObjectDigestInfo(ObjectDigestInfo::TYPE_PUBLIC_KEY, 
			new SHA1WithRSAEncryptionAlgorithmIdentifier(), new BitString(""));
	}
	
	public static function tearDownAfterClass() {
		self::$_issuerSerial = null;
		self::$_subject = null;
		self::$_odi = null;
	}
	
	public function testCreate() {
		$holder = new Holder(self::$_issuerSerial, self::$_subject);
		$holder = $holder->withObjectDigestInfo(self::$_odi);
		$this->assertInstanceOf(Holder::class, $holder);
		return $holder;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Holder $holder
	 */
	public function testEncode(Holder $holder) {
		$seq = $holder->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$holder = Holder::fromASN1(Sequence::fromDER($data));
		$this->assertInstanceOf(Holder::class, $holder);
		return $holder;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Holder $ref
	 * @param Holder $new
	 */
	public function testRecoded(Holder $ref, Holder $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Holder $holder
	 */
	public function testBaseCertificateID(Holder $holder) {
		$this->assertEquals(self::$_issuerSerial, $holder->baseCertificateID());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Holder $holder
	 */
	public function testEntityName(Holder $holder) {
		$this->assertEquals(self::$_subject, $holder->entityName());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Holder $holder
	 */
	public function testObjectDigestInfo(Holder $holder) {
		$this->assertEquals(self::$_odi, $holder->objectDigestInfo());
	}
	
	public function testWithBaseCertificateID() {
		$holder = new Holder();
		$holder = $holder->withBaseCertificateID(self::$_issuerSerial);
		$this->assertInstanceOf(Holder::class, $holder);
	}
	
	public function testWithEntityName() {
		$holder = new Holder();
		$holder = $holder->withEntityName(self::$_subject);
		$this->assertInstanceOf(Holder::class, $holder);
	}
	
	public function testWithObjectDigestInfo() {
		$holder = new Holder();
		$holder = $holder->withObjectDigestInfo(self::$_odi);
		$this->assertInstanceOf(Holder::class, $holder);
	}
	
	/**
	 * @expectedException LogicException
	 */
	public function testNoBaseCertificateIDFail() {
		$holder = new Holder();
		$holder->baseCertificateID();
	}
	
	/**
	 * @expectedException LogicException
	 */
	public function testNoEntityNameFail() {
		$holder = new Holder();
		$holder->entityName();
	}
	
	/**
	 * @expectedException LogicException
	 */
	public function testNoObjectDigestInfoFail() {
		$holder = new Holder();
		$holder->objectDigestInfo();
	}
}
