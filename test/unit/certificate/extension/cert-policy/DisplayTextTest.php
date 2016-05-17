<?php

use ASN1\Element;
use ASN1\Type\Primitive\BMPString;
use ASN1\Type\Primitive\IA5String;
use ASN1\Type\Primitive\UTF8String;
use ASN1\Type\Primitive\VisibleString;
use ASN1\Type\StringType;
use X509\Certificate\Extension\CertificatePolicy\DisplayText;


/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 */
class DisplayTextTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$dt = DisplayText::fromString("test");
		$this->assertInstanceOf(DisplayText::class, $dt);
		return $dt;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param DisplayText $dt
	 */
	public function testEncode(DisplayText $dt) {
		$el = $dt->toASN1();
		$this->assertInstanceOf(StringType::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$qual = DisplayText::fromASN1(StringType::fromDER($data));
		$this->assertInstanceOf(DisplayText::class, $qual);
		return $qual;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param DisplayText $ref
	 * @param DisplayText $new
	 */
	public function testRecoded(DisplayText $ref, DisplayText $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param DisplayText $dt
	 */
	public function testString(DisplayText $dt) {
		$this->assertEquals("test", $dt->string());
	}
	
	public function testEncodeIA5String() {
		$dt = new DisplayText("", Element::TYPE_IA5_STRING);
		$this->assertInstanceOf(IA5String::class, $dt->toASN1());
	}
	
	public function testEncodeVisibleString() {
		$dt = new DisplayText("", Element::TYPE_VISIBLE_STRING);
		$this->assertInstanceOf(VisibleString::class, $dt->toASN1());
	}
	
	public function testEncodeBMPString() {
		$dt = new DisplayText("", Element::TYPE_BMP_STRING);
		$this->assertInstanceOf(BMPString::class, $dt->toASN1());
	}
	
	public function testEncodeUTF8String() {
		$dt = new DisplayText("", Element::TYPE_UTF8_STRING);
		$this->assertInstanceOf(UTF8String::class, $dt->toASN1());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testEncodeUnsupportedTypeFail() {
		$dt = new DisplayText("", Element::TYPE_NULL);
		$dt->toASN1();
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param DisplayText $dt
	 */
	public function testToString(DisplayText $dt) {
		$this->assertInternalType("string", strval($dt));
	}
}
