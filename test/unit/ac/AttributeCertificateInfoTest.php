<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use X501\ASN1\Name;
use X509\AttributeCertificate\AttCertIssuer;
use X509\AttributeCertificate\AttCertValidityPeriod;
use X509\AttributeCertificate\Attribute\RoleAttributeValue;
use X509\AttributeCertificate\AttributeCertificateInfo;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Holder;
use X509\AttributeCertificate\IssuerSerial;
use X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use X509\Certificate\Extensions;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group ac
 */
class AttributeCertificateInfoTest extends PHPUnit_Framework_TestCase
{
	const ISSUER_DN = "cn=Issuer";
	
	private static $_holder;
	
	private static $_issuer;
	
	private static $_validity;
	
	private static $_attribs;
	
	private static $_extensions;
	
	public static function setUpBeforeClass() {
		self::$_holder = new Holder(
			new IssuerSerial(
				new GeneralNames(DirectoryName::fromDNString(self::ISSUER_DN)), 
				42));
		self::$_issuer = AttCertIssuer::fromName(
			Name::fromString(self::ISSUER_DN));
		self::$_validity = AttCertValidityPeriod::fromStrings(
			"2016-04-29 12:00:00", "2016-04-29 13:00:00");
		self::$_attribs = Attributes::fromAttributeValues(
			new RoleAttributeValue(new UniformResourceIdentifier("urn:admin")));
		self::$_extensions = new Extensions(
			new AuthorityKeyIdentifierExtension(true, "test"));
	}
	
	public static function tearDownAfterClass() {
		self::$_holder = null;
		self::$_issuer = null;
		self::$_validity = null;
		self::$_attribs = null;
		self::$_extensions = null;
	}
	
	public function testCreate() {
		$aci = new AttributeCertificateInfo(self::$_holder, self::$_issuer, 
			self::$_validity, self::$_attribs);
		$aci = $aci->withSignature(
			new SHA256WithRSAEncryptionAlgorithmIdentifier())
			->withSerial(1)
			->withExtensions(self::$_extensions);
		$this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
		return $aci;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testEncode(AttributeCertificateInfo $aci) {
		$seq = $aci->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$tc = AttributeCertificateInfo::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(AttributeCertificateInfo::class, $tc);
		return $tc;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param AttributeCertificateInfo $ref
	 * @param AttributeCertificateInfo $new
	 */
	public function testRecoded(AttributeCertificateInfo $ref, 
			AttributeCertificateInfo $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testVersion(AttributeCertificateInfo $aci) {
		$this->assertEquals(AttributeCertificateInfo::VERSION_2, 
			$aci->version());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testHolder(AttributeCertificateInfo $aci) {
		$this->assertEquals(self::$_holder, $aci->holder());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testIssuer(AttributeCertificateInfo $aci) {
		$this->assertEquals(self::$_issuer, $aci->issuer());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testSignature(AttributeCertificateInfo $aci) {
		$this->assertEquals(new SHA256WithRSAEncryptionAlgorithmIdentifier(), 
			$aci->signature());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testSerialNumber(AttributeCertificateInfo $aci) {
		$this->assertEquals(1, $aci->serialNumber());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testValidityPeriod(AttributeCertificateInfo $aci) {
		$this->assertEquals(self::$_validity, $aci->validityPeriod());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testAttributes(AttributeCertificateInfo $aci) {
		$this->assertEquals(self::$_attribs, $aci->attributes());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeCertificateInfo $aci
	 */
	public function testExtensions(AttributeCertificateInfo $aci) {
		$this->assertEquals(self::$_extensions, $aci->extensions());
	}
}
