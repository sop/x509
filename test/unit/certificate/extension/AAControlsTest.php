<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\AAControlsExtension;
use X509\Certificate\Extension\Extension;


/**
 * @group certificate
 * @group extension
 */
class AAControlsTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$ext = new AAControlsExtension(true, 3, array("1.2.3.4"), 
			array("1.2.3.5", "1.2.3.6"), false);
		$this->assertInstanceOf(AAControlsExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testOID(Extension $ext) {
		$this->assertEquals(Extension::OID_AA_CONTROLS, $ext->oid());
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
		$ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(AAControlsExtension::class, $ext);
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
	 * @param AAControlsExtension $ext
	 */
	public function testPathLen(AAControlsExtension $ext) {
		$this->assertEquals(3, $ext->pathLen());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param AAControlsExtension $ext
	 */
	public function testPermitted(AAControlsExtension $ext) {
		$this->assertEquals(array("1.2.3.4"), $ext->permittedAttrs());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param AAControlsExtension $ext
	 */
	public function testExcluded(AAControlsExtension $ext) {
		$this->assertEquals(array("1.2.3.5", "1.2.3.6"), $ext->excludedAttrs());
	}
	
	/**
	 * @depends testDecode
	 *
	 * @param AAControlsExtension $ext
	 */
	public function testUnspecified(AAControlsExtension $ext) {
		$this->assertFalse($ext->permitUnspecified());
	}
	
	public function testCreateEmpty() {
		$ext = new AAControlsExtension(false);
		$this->assertInstanceOf(AAControlsExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreateEmpty
	 *
	 * @param Extension $ext
	 */
	public function testEncodeEmpty(Extension $ext) {
		$seq = $ext->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncodeEmpty
	 *
	 * @param string $der
	 */
	public function testDecodeEmpty($der) {
		$ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(AAControlsExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreateEmpty
	 * @depends testDecodeEmpty
	 *
	 * @param Extension $ref
	 * @param Extension $new
	 */
	public function testRecodedEmpty(Extension $ref, Extension $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreateEmpty
	 * @expectedException LogicException
	 *
	 * @param AAControlsExtension $ext
	 */
	public function testNoPathLenFail(AAControlsExtension $ext) {
		$ext->pathLen();
	}
	
	/**
	 * @depends testCreateEmpty
	 * @expectedException LogicException
	 *
	 * @param AAControlsExtension $ext
	 */
	public function testNoPermittedAttrsFail(AAControlsExtension $ext) {
		$ext->permittedAttrs();
	}
	
	/**
	 * @depends testCreateEmpty
	 * @expectedException LogicException
	 *
	 * @param AAControlsExtension $ext
	 */
	public function testNoExcludedAttrsFail(AAControlsExtension $ext) {
		$ext->excludedAttrs();
	}
}
