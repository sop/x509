<?php

use ASN1\Element;
use ASN1\Type\Tagged\ImplicitTagging;
use ASN1\Type\TaggedType;
use X509\GeneralName\GeneralName;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group general-name
 */
class URINameTest extends PHPUnit_Framework_TestCase
{
	const URI = "urn:test";
	
	public function testCreate() {
		$uri = new UniformResourceIdentifier(self::URI);
		$this->assertInstanceOf(UniformResourceIdentifier::class, $uri);
		return $uri;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param UniformResourceIdentifier $uri
	 */
	public function testEncode(UniformResourceIdentifier $uri) {
		$el = $uri->toASN1();
		$this->assertInstanceOf(ImplicitTagging::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testChoiceTag($der) {
		$el = TaggedType::fromDER($der);
		$this->assertEquals(GeneralName::TAG_URI, $el->tag());
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$uri = UniformResourceIdentifier::fromASN1(Element::fromDER($der));
		$this->assertInstanceOf(UniformResourceIdentifier::class, $uri);
		return $uri;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param UniformResourceIdentifier $ref
	 * @param UniformResourceIdentifier $new
	 */
	public function testRecoded(UniformResourceIdentifier $ref, 
			UniformResourceIdentifier $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param UniformResourceIdentifier $uri
	 */
	public function testString(UniformResourceIdentifier $uri) {
		$this->assertEquals(self::URI, $uri->string());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param UniformResourceIdentifier $uri
	 */
	public function testURI(UniformResourceIdentifier $uri) {
		$this->assertEquals(self::URI, $uri->uri());
	}
}
