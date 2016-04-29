<?php

use ASN1\Type\Constructed\Sequence;
use X501\ASN1\AttributeType;
use X501\ASN1\AttributeValue\AttributeValue;
use X509\AttributeCertificate\Attribute\RoleAttributeValue;
use X509\AttributeCertificate\Attributes;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group ac
 * @group attribute
 */
class RoleAttributeTest extends PHPUnit_Framework_TestCase
{
	const ROLE_URI = "urn:administartor";
	
	const AUTHORITY_DN = "cn=Role Authority";
	
	public function testCreate() {
		$value = new RoleAttributeValue(
			new UniformResourceIdentifier(self::ROLE_URI), 
			new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN)));
		$this->assertInstanceOf(RoleAttributeValue::class, $value);
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
		$value = RoleAttributeValue::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(RoleAttributeValue::class, $value);
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
		$this->assertEquals(AttributeType::OID_ROLE, $value->oid());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param RoleAttributeValue $value
	 */
	public function testRoleName(RoleAttributeValue $value) {
		$this->assertEquals(self::ROLE_URI, $value->roleName());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param RoleAttributeValue $value
	 */
	public function testRoleAuthority(RoleAttributeValue $value) {
		$this->assertEquals(self::AUTHORITY_DN, 
			$value->roleAuthority()
				->firstDN());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AttributeValue $value
	 */
	public function testAttributes(AttributeValue $value) {
		$attribs = Attributes::fromAttributeValues($value);
		$this->assertTrue($attribs->hasRole());
		return $attribs;
	}
	
	/**
	 * @depends testAttributes
	 *
	 * @param Attributes $attribs
	 */
	public function testFromAttributes(Attributes $attribs) {
		$this->assertInstanceOf(RoleAttributeValue::class, $attribs->role());
	}
}
