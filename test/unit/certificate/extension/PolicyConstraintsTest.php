<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\PolicyConstraintsExtension;
use X509\Certificate\Extensions;


/**
 * @group certificate
 * @group extension
 */
class PolicyConstraintsTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$ext = new PolicyConstraintsExtension(true, 2, 3);
		$this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testOID(Extension $ext) {
		$this->assertEquals(Extension::OID_POLICY_CONSTRAINTS, $ext->oid());
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
		$ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
	 * @param PolicyConstraintsExtension $ext
	 */
	public function testRequireExplicit(PolicyConstraintsExtension $ext) {
		$this->assertEquals(2, $ext->requireExplicitPolicy());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PolicyConstraintsExtension $ext
	 */
	public function testInhibitMapping(PolicyConstraintsExtension $ext) {
		$this->assertEquals(3, $ext->inhibitPolicyMapping());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PolicyConstraintsExtension $ext
	 */
	public function testExtensions(PolicyConstraintsExtension $ext) {
		$extensions = new Extensions($ext);
		$this->assertTrue($extensions->hasPolicyConstraints());
		return $extensions;
	}
	
	/**
	 * @depends testExtensions
	 *
	 * @param Extensions $exts
	 */
	public function testFromExtensions(Extensions $exts) {
		$ext = $exts->policyConstraints();
		$this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
	}
	
	public function testCreateEmpty() {
		$ext = new PolicyConstraintsExtension(false);
		$this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
		$ext = PolicyConstraintsExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
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
	 * @param PolicyConstraintsExtension $ext
	 */
	public function testNoRequireExplicitFail(PolicyConstraintsExtension $ext) {
		$ext->requireExplicitPolicy();
	}
	
	/**
	 * @depends testCreateEmpty
	 * @expectedException LogicException
	 *
	 * @param PolicyConstraintsExtension $ext
	 */
	public function testNoInhibitMappingFail(PolicyConstraintsExtension $ext) {
		$ext->inhibitPolicyMapping();
	}
}
