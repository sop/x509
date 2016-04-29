<?php

use ASN1\Element;
use ASN1\Type\Tagged\ImplicitTagging;
use ASN1\Type\TaggedType;
use X509\GeneralName\GeneralName;
use X509\GeneralName\IPAddress;
use X509\GeneralName\IPv6Address;


/**
 * @group general-name
 */
class IPv6AddressNameTest extends PHPUnit_Framework_TestCase
{
	public function testCreateIPv6() {
		// @todo implement compressed form handling
		$ip = new IPv6Address("0000:0000:0000:0000:0000:0000:0000:0001");
		$this->assertInstanceOf(IPAddress::class, $ip);
		return $ip;
	}
	
	/**
	 * @depends testCreateIPv6
	 *
	 * @param IPAddress $ip
	 */
	public function testEncodeIPv6(IPAddress $ip) {
		$el = $ip->toASN1();
		$this->assertInstanceOf(ImplicitTagging::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncodeIPv6
	 *
	 * @param string $der
	 */
	public function testChoiceTag($der) {
		$el = TaggedType::fromDER($der);
		$this->assertEquals(GeneralName::TAG_IP_ADDRESS, $el->tag());
	}
	
	/**
	 * @depends testEncodeIPv6
	 *
	 * @param string $der
	 */
	public function testDecodeIPv6($der) {
		$ip = IPAddress::fromASN1(Element::fromDER($der));
		$this->assertInstanceOf(IPAddress::class, $ip);
		return $ip;
	}
	
	/**
	 * @depends testCreateIPv6
	 * @depends testDecodeIPv6
	 *
	 * @param IPAddress $ref
	 * @param IPAddress $new
	 */
	public function testRecoded(IPAddress $ref, IPAddress $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreateIPv6
	 *
	 * @param IPAddress $ip
	 */
	public function testIPv6(IPAddress $ip) {
		$this->assertEquals("0000:0000:0000:0000:0000:0000:0000:0001", 
			$ip->address());
	}
}
