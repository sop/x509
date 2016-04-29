<?php

use ASN1\Type\Constructed\Sequence;
use X501\ASN1\Name;
use X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extensions;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;


/**
 * @group certificate
 * @group extension
 */
class AuthorityKeyIdentifierTest extends PHPUnit_Framework_TestCase
{
	const KEY_ID = "test-id";
	
	const SERIAL = 42;
	
	private static $_issuer;
	
	public static function setUpBeforeClass() {
		self::$_issuer = new GeneralNames(
			new DirectoryName(Name::fromString("cn=Issuer")));
	}
	
	public static function tearDownAfterClass() {
		self::$_issuer = null;
	}
	
	public function testCreate() {
		$ext = new AuthorityKeyIdentifierExtension(true, self::KEY_ID, 
			self::$_issuer, self::SERIAL);
		$this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testOID(Extension $ext) {
		$this->assertEquals(Extension::OID_AUTHORITY_KEY_IDENTIFIER, 
			$ext->oid());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testCritical(Extension $ext) {
		$this->assertTrue($ext->isCritical());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testEncode(Extension $ext) {
		$seq = $ext->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$ext = AuthorityKeyIdentifierExtension::fromASN1(
			Sequence::fromDER($der));
		$this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Extension $ref
	 * @param Extension $new
	 */
	public function testRecoded(Extension $ref, Extension $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AuthorityKeyIdentifierExtension $ext
	 */
	public function testKeyIdentifier(AuthorityKeyIdentifierExtension $ext) {
		$this->assertEquals(self::KEY_ID, $ext->keyIdentifier());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AuthorityKeyIdentifierExtension $ext
	 */
	public function testIssuer(AuthorityKeyIdentifierExtension $ext) {
		$this->assertEquals(self::$_issuer, $ext->issuer());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AuthorityKeyIdentifierExtension $ext
	 */
	public function testSerial(AuthorityKeyIdentifierExtension $ext) {
		$this->assertEquals(self::SERIAL, $ext->serial());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AuthorityKeyIdentifierExtension $ext
	 */
	public function testExtensions(AuthorityKeyIdentifierExtension $ext) {
		$extensions = new Extensions($ext);
		$this->assertTrue($extensions->hasAuthorityKeyIdentifier());
		return $extensions;
	}
	
	/**
	 * @depends testExtensions
	 *
	 * @param Extensions $exts
	 */
	public function testFromExtensions(Extensions $exts) {
		$ext = $exts->authorityKeyIdentifier();
		$this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
	}
}
