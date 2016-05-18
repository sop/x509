<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use X509\GeneralName\GeneralName;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group certificate
 * @group extension
 * @group name-constraint
 */
class GeneralSubtreeTest extends PHPUnit_Framework_TestCase
{
	const URI = ".example.com";
	
	public function testCreate() {
		$subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI));
		$this->assertInstanceOf(GeneralSubtree::class, $subtree);
		return $subtree;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralSubtree $subtree
	 */
	public function testEncode(GeneralSubtree $subtree) {
		$el = $subtree->toASN1();
		$this->assertInstanceOf(Sequence::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
		$this->assertInstanceOf(GeneralSubtree::class, $subtree);
		return $subtree;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param GeneralSubtree $ref
	 * @param GeneralSubtree $new
	 */
	public function testRecoded(GeneralSubtree $ref, GeneralSubtree $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralSubtree $subtree
	 */
	public function testBase(GeneralSubtree $subtree) {
		$base = $subtree->base();
		$this->assertInstanceOf(GeneralName::class, $base);
	}
	
	public function testCreateWithAll() {
		$subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI), 
			1, 3);
		$this->assertInstanceOf(GeneralSubtree::class, $subtree);
		return $subtree;
	}
	
	/**
	 * @depends testCreateWithAll
	 *
	 * @param GeneralSubtree $subtree
	 */
	public function testEncodeWithAll(GeneralSubtree $subtree) {
		$el = $subtree->toASN1();
		$this->assertInstanceOf(Sequence::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncodeWithAll
	 *
	 * @param string $data
	 */
	public function testDecodeWithAll($data) {
		$subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
		$this->assertInstanceOf(GeneralSubtree::class, $subtree);
		return $subtree;
	}
	
	/**
	 * @depends testCreateWithAll
	 * @depends testDecodeWithAll
	 *
	 * @param GeneralSubtree $ref
	 * @param GeneralSubtree $new
	 */
	public function testRecodedWithAll(GeneralSubtree $ref, GeneralSubtree $new) {
		$this->assertEquals($ref, $new);
	}
}
