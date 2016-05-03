<?php

use ASN1\Type\Constructed\Sequence;
use X501\ASN1\AttributeValue\AttributeValue;
use X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
use X509\AttributeCertificate\Attribute\IetfAttrValue;
use X509\AttributeCertificate\Attributes;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;


/**
 * @group ac
 * @group attribute
 */
class ChargingIdentityAttributeTest extends PHPUnit_Framework_TestCase
{
	const AUTHORITY_DN = "cn=Authority Name";
	const OCTETS_VAL = "octet string";
	const OID_VAL = "1.3.6.1.3.1";
	const UTF8_VAL = "UTF-8 string";
	
	public function testCreate() {
		$value = new ChargingIdentityAttributeValue(
			IetfAttrValue::fromOctets(self::OCTETS_VAL), 
			IetfAttrValue::fromOID(self::OID_VAL), 
			IetfAttrValue::fromString(self::UTF8_VAL));
		$value = $value->withPolicyAuthority(
			new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN)));
		$this->assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
		return $value;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeValue $value
	 */
	public function testEncode(AttributeValue $value) {
		$el = $value->toASN1();
		$this->assertInstanceOf(Sequence::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param unknown $der
	 */
	public function testDecode($der) {
		$value = ChargingIdentityAttributeValue::fromASN1(
			Sequence::fromDER($der));
		$this->assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
		return $value;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param AttributeValue $ref
	 * @param AttributeValue $new
	 */
	public function testRecoded(AttributeValue $ref, AttributeValue $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeValue $value
	 */
	public function testOID(AttributeValue $value) {
		$this->assertEquals(ChargingIdentityAttributeValue::OID, $value->oid());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ChargingIdentityAttributeValue $value
	 */
	public function testAuthority(ChargingIdentityAttributeValue $value) {
		$this->assertEquals(self::AUTHORITY_DN, 
			$value->policyAuthority()
				->firstDN());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ChargingIdentityAttributeValue $value
	 */
	public function testCount(ChargingIdentityAttributeValue $value) {
		$this->assertCount(3, $value);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ChargingIdentityAttributeValue $value
	 */
	public function testIterator(ChargingIdentityAttributeValue $value) {
		$values = array();
		foreach ($value as $val) {
			$values[] = $val;
		}
		$this->assertCount(3, $values);
		$this->assertContainsOnlyInstancesOf(IetfAttrValue::class, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ChargingIdentityAttributeValue $value
	 */
	public function testOctetStringValue(ChargingIdentityAttributeValue $value) {
		$this->assertEquals(self::OCTETS_VAL, $value->values()[0]);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ChargingIdentityAttributeValue $value
	 */
	public function testOIDValue(ChargingIdentityAttributeValue $value) {
		$this->assertEquals(self::OID_VAL, $value->values()[1]);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ChargingIdentityAttributeValue $value
	 */
	public function testUTF8Value(ChargingIdentityAttributeValue $value) {
		$this->assertEquals(self::UTF8_VAL, $value->values()[2]);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeValue $value
	 */
	public function testAttributes(AttributeValue $value) {
		$attribs = Attributes::fromAttributeValues($value);
		$this->assertTrue($attribs->hasChargingIdentity());
		return $attribs;
	}
	
	/**
	 * @depends testAttributes
	 *
	 * @param Attributes $attribs
	 */
	public function testFromAttributes(Attributes $attribs) {
		$this->assertInstanceOf(ChargingIdentityAttributeValue::class, 
			$attribs->chargingIdentity());
	}
}
