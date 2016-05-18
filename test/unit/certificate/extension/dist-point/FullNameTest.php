<?php

use ASN1\Type\Tagged\ImplicitTagging;
use ASN1\Type\TaggedType;
use X509\Certificate\Extension\DistributionPoint\FullName;
use X509\GeneralName\GeneralNames;


/**
 * @group certificate
 * @group extension
 * @group distribution-point
 */
class FullNameTest extends PHPUnit_Framework_TestCase
{
	const URI = "urn:test";
	
	public function testCreate() {
		$name = FullName::fromURI(self::URI);
		$this->assertInstanceOf(FullName::class, $name);
		return $name;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param FullName $name
	 */
	public function testEncode(FullName $name) {
		$el = $name->toASN1();
		$this->assertInstanceOf(ImplicitTagging::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$name = FullName::fromTaggedType(TaggedType::fromDER($data));
		$this->assertInstanceOf(FullName::class, $name);
		return $name;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param FullName $ref
	 * @param FullName $new
	 */
	public function testRecoded(FullName $ref, FullName $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param FullName $name
	 */
	public function testNames(FullName $name) {
		$names = $name->names();
		$this->assertInstanceOf(GeneralNames::class, $names);
	}
}
