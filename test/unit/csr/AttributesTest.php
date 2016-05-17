<?php

use ASN1\Type\Constructed\Set;
use X501\ASN1\Attribute;
use X509\Certificate\Extensions;
use X509\CertificationRequest\Attribute\ExtensionRequestValue;
use X509\CertificationRequest\Attributes;


/**
 * @group csr
 * @group attribute
 */
class CSRAttributesTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$attribs = Attributes::fromAttributeValues(
			new ExtensionRequestValue(new Extensions()));
		$this->assertInstanceOf(Attributes::class, $attribs);
		return $attribs;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Attributes $attribs
	 */
	public function testEncode(Attributes $attribs) {
		$seq = $attribs->toASN1();
		$this->assertInstanceOf(Set::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$attribs = Attributes::fromASN1(Set::fromDER($data));
		$this->assertInstanceOf(Attributes::class, $attribs);
		return $attribs;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Attributes $ref
	 * @param Attributes $new
	 */
	public function testRecoded(Attributes $ref, Attributes $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Attributes $attribs
	 */
	public function testExtensionRequest(Attributes $attribs) {
		$this->assertInstanceOf(ExtensionRequestValue::class, 
			$attribs->extensionRequest());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Attributes $attribs
	 */
	public function testAll(Attributes $attribs) {
		$this->assertContainsOnlyInstancesOf(Attribute::class, $attribs->all());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Attributes $attribs
	 */
	public function testCount(Attributes $attribs) {
		$this->assertCount(1, $attribs);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Attributes $attribs
	 */
	public function testIterator(Attributes $attribs) {
		$values = array();
		foreach ($attribs as $attr) {
			$values[] = $attr;
		}
		$this->assertContainsOnlyInstancesOf(Attribute::class, $values);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param Attributes $attribs
	 */
	public function testFirstOfFail(Attributes $attribs) {
		$attribs->firstOf("1.3.6.1.3");
	}
	
	/**
	 * @expectedException LogicException
	 */
	public function testNoExtensionRequestFail() {
		$attribs = new Attributes();
		$attribs->extensionRequest();
	}
}
