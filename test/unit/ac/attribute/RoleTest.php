<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use X501\ASN1\AttributeType;
use X501\ASN1\AttributeValue\AttributeValue;
use X501\MatchingRule\MatchingRule;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Attribute\RoleAttributeValue;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 * @group attribute
 */
class RoleAttributeTest extends \PHPUnit\Framework\TestCase
{
    const ROLE_URI = "urn:administrator";
    
    const AUTHORITY_DN = "cn=Role Authority";
    
    public function testCreate()
    {
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
    public function testEncode(AttributeValue $value)
    {
        $el = $value->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $value = RoleAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
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
    public function testRecoded(AttributeValue $ref, AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testOID(AttributeValue $value)
    {
        $this->assertEquals(AttributeType::OID_ROLE, $value->oid());
    }
    
    public function testFromString()
    {
        $value = RoleAttributeValue::fromString(self::ROLE_URI,
            new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN)));
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
    }
    
    /**
     * @depends testCreate
     *
     * @param RoleAttributeValue $value
     */
    public function testRoleName(RoleAttributeValue $value)
    {
        $this->assertEquals(self::ROLE_URI, $value->roleName());
    }
    
    /**
     * @depends testCreate
     *
     * @param RoleAttributeValue $value
     */
    public function testRoleAuthority(RoleAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN,
            $value->roleAuthority()
                ->firstDN());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasRole());
        return $attribs;
    }
    
    /**
     * @depends testAttributes
     *
     * @param Attributes $attribs
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(RoleAttributeValue::class, $attribs->role());
    }
    
    /**
     * @depends testAttributes
     *
     * @param Attributes $attribs
     */
    public function testAllFromAttributes(Attributes $attribs)
    {
        $this->assertContainsOnlyInstancesOf(RoleAttributeValue::class,
            $attribs->roles());
    }
    
    public function testAllFromMultipleAttributes()
    {
        $attribs = Attributes::fromAttributeValues(
            RoleAttributeValue::fromString("urn:role:1"),
            RoleAttributeValue::fromString("urn:role:2"));
        $this->assertCount(2, $attribs->roles());
    }
    
    public function testCreateWithoutAuthority()
    {
        $value = new RoleAttributeValue(
            new UniformResourceIdentifier(self::ROLE_URI));
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }
    
    /**
     * @depends testCreateWithoutAuthority
     *
     * @param AttributeValue $value
     */
    public function testEncodeWithoutAuthority(AttributeValue $value)
    {
        $el = $value->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncodeWithoutAuthority
     *
     * @param string $der
     */
    public function testDecodeWithoutAuthority($der)
    {
        $value = RoleAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }
    
    /**
     * @depends testCreateWithoutAuthority
     * @depends testDecodeWithoutAuthority
     *
     * @param AttributeValue $ref
     * @param AttributeValue $new
     */
    public function testRecodedWithoutAuthority(AttributeValue $ref,
        AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithoutAuthority
     * @expectedException LogicException
     *
     * @param RoleAttributeValue $value
     */
    public function testNoRoleAuthorityFail(RoleAttributeValue $value)
    {
        $value->roleAuthority();
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testStringValue(AttributeValue $value)
    {
        $this->assertInternalType("string", $value->stringValue());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testEqualityMatchingRule(AttributeValue $value)
    {
        $this->assertInstanceOf(MatchingRule::class,
            $value->equalityMatchingRule());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testRFC2253String(AttributeValue $value)
    {
        $this->assertInternalType("string", $value->rfc2253String());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testToString(AttributeValue $value)
    {
        $this->assertInternalType("string", strval($value));
    }
}
