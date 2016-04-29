<?php

use ASN1\Element;
use ASN1\Type\Tagged\ImplicitTagging;
use ASN1\Type\TaggedType;
use X509\GeneralName\GeneralName;
use X509\GeneralName\IPAddress;
use X509\GeneralName\IPv4Address;


/**
 * @group general-name
 */
class IPv4AddressNameTest extends PHPUnit_Framework_TestCase
{
	public function testCreateIPv4() {
		$ip = new IPv4Address("127.0.0.1");
		$this->assertInstanceOf(IPAddress::class, $ip);
		return $ip;
	}
	
	/**
	 * @depends testCreateIPv4
	 *
	 * @param IPAddress $ip
	 */
	public function testEncodeIPv4(IPAddress $ip) {
		$el = $ip->toASN1();
		$this->assertInstanceOf(ImplicitTagging::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncodeIPv4
	 *
	 * @param string $der
	 */
	public function testChoiceTag($der) {
		$el = TaggedType::fromDER($der);
		$this->assertEquals(GeneralName::TAG_IP_ADDRESS, $el->tag());
	}
	
	/**
	 * @depends testEncodeIPv4
	 *
	 * @param string $der
	 */
	public function testDecodeIPv4($der) {
		$ip = IPAddress::fromASN1(Element::fromDER($der));
		$this->assertInstanceOf(IPAddress::class, $ip);
		return $ip;
	}
	
	/**
	 * @depends testCreateIPv4
	 * @depends testDecodeIPv4
	 *
	 * @param IPAddress $ref
	 * @param IPAddress $new
	 */
	public function testRecoded(IPAddress $ref, IPAddress $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreateIPv4
	 *
	 * @param IPAddress $ip
	 */
	public function testIPv4(IPAddress $ip) {
		$this->assertEquals("127.0.0.1", $ip->address());
	}
}
