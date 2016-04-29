<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use X509\Certificate\Extensions;


/**
 * @group certificate
 * @group extension
 */
class SubjectKeyIdentifierTest extends PHPUnit_Framework_TestCase
{
	const KEY_ID = "test-id";
	
	public function testCreate() {
		$ext = new SubjectKeyIdentifierExtension(true, self::KEY_ID);
		$this->assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testOID(Extension $ext) {
		$this->assertEquals(Extension::OID_SUBJECT_KEY_IDENTIFIER, $ext->oid());
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
		$ext = SubjectKeyIdentifierExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
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
	 * @param SubjectKeyIdentifierExtension $ext
	 */
	public function testKeyIdentifier(SubjectKeyIdentifierExtension $ext) {
		$this->assertEquals(self::KEY_ID, $ext->keyIdentifier());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param SubjectKeyIdentifierExtension $ext
	 */
	public function testExtensions(SubjectKeyIdentifierExtension $ext) {
		$extensions = new Extensions($ext);
		$this->assertTrue($extensions->hasSubjectKeyIdentifier());
		return $extensions;
	}
	
	/**
	 * @depends testExtensions
	 *
	 * @param Extensions $exts
	 */
	public function testFromExtensions(Extensions $exts) {
		$ext = $exts->subjectKeyIdentifier();
		$this->assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
	}
}
