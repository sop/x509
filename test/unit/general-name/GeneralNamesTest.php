<?php

use ASN1\Type\Constructed\Sequence;
use X509\GeneralName\DNSName;
use X509\GeneralName\GeneralName;
use X509\GeneralName\GeneralNames;


/**
 * @group general-name
 */
class GeneralNamesTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$gns = new GeneralNames(new DNSName("test1"), new DNSName("test2"));
		$this->assertInstanceOf(GeneralNames::class, $gns);
		return $gns;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testEncode(GeneralNames $gns) {
		$seq = $gns->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$gns = GeneralNames::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(GeneralNames::class, $gns);
		return $gns;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param GeneralNames $ref
	 * @param GeneralNames $new
	 */
	public function testRecoded(GeneralNames $ref, GeneralNames $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testHas(GeneralNames $gns) {
		$this->assertTrue($gns->has(GeneralName::TAG_DNS_NAME));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testHasNot(GeneralNames $gns) {
		$this->assertFalse($gns->has(GeneralName::TAG_URI));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testAllOf(GeneralNames $gns) {
		$this->assertCount(2, $gns->allOf(GeneralName::TAG_DNS_NAME));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testFirstOf(GeneralNames $gns) {
		$this->assertInstanceOf(DNSName::class, 
			$gns->firstOf(GeneralName::TAG_DNS_NAME));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testCount(GeneralNames $gns) {
		$this->assertCount(2, $gns);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GeneralNames $gns
	 */
	public function testIterator(GeneralNames $gns) {
		$values = array();
		foreach ($gns as $gn) {
			$values[] = $gn;
		}
		$this->assertCount(2, $values);
		$this->assertContainsOnlyInstancesOf(GeneralName::class, $values);
	}
}
