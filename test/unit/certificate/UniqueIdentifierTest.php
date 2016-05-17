<?php

use ASN1\Type\Primitive\BitString;
use X509\Certificate\UniqueIdentifier;


/**
 * @group certificate
 */
class UniqueIdentifierTest extends PHPUnit_Framework_TestCase
{
	const UID = "urn:test";
	
	public function testCreate() {
		$id = UniqueIdentifier::fromString(self::UID);
		$this->assertInstanceOf(UniqueIdentifier::class, $id);
		return $id;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param UniqueIdentifier $id
	 */
	public function testEncode(UniqueIdentifier $id) {
		$bs = $id->toASN1();
		$this->assertInstanceOf(BitString::class, $bs);
		return $bs->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$id = UniqueIdentifier::fromASN1(BitString::fromDER($der));
		$this->assertInstanceOf(UniqueIdentifier::class, $id);
		return $id;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param UniqueIdentifier $ref
	 * @param UniqueIdentifier $new
	 */
	public function testRecoded(UniqueIdentifier $ref, UniqueIdentifier $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param UniqueIdentifier $id
	 */
	public function testString(UniqueIdentifier $id) {
		$this->assertEquals(self::UID, $id->string());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param UniqueIdentifier $id
	 */
	public function testBitString(UniqueIdentifier $id) {
		$this->assertInstanceOf(BitString::class, $id->bitString());
	}
}
