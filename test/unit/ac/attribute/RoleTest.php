<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 * @group attribute
 *
 * @internal
 */
class RoleAttributeTest extends TestCase
{
    public const ROLE_URI = 'urn:administrator';

    public const AUTHORITY_DN = 'cn=Role Authority';

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
     */
    public function testRecoded(AttributeValue $ref, AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
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
     */
    public function testRoleName(RoleAttributeValue $value)
    {
        $this->assertEquals(self::ROLE_URI, $value->roleName());
    }

    /**
     * @depends testCreate
     */
    public function testRoleAuthority(RoleAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN,
            $value->roleAuthority()
                ->firstDN());
    }

    /**
     * @depends testCreate
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasRole());
        return $attribs;
    }

    /**
     * @depends testAttributes
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(RoleAttributeValue::class, $attribs->role());
    }

    /**
     * @depends testAttributes
     */
    public function testAllFromAttributes(Attributes $attribs)
    {
        $this->assertContainsOnlyInstancesOf(RoleAttributeValue::class,
            $attribs->roles());
    }

    public function testAllFromMultipleAttributes()
    {
        $attribs = Attributes::fromAttributeValues(
            RoleAttributeValue::fromString('urn:role:1'),
            RoleAttributeValue::fromString('urn:role:2'));
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
     */
    public function testRecodedWithoutAuthority(AttributeValue $ref,
        AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateWithoutAuthority
     */
    public function testNoRoleAuthorityFail(RoleAttributeValue $value)
    {
        $this->expectException(LogicException::class);
        $value->roleAuthority();
    }

    /**
     * @depends testCreate
     */
    public function testStringValue(AttributeValue $value)
    {
        $this->assertIsString($value->stringValue());
    }

    /**
     * @depends testCreate
     */
    public function testEqualityMatchingRule(AttributeValue $value)
    {
        $this->assertInstanceOf(MatchingRule::class,
            $value->equalityMatchingRule());
    }

    /**
     * @depends testCreate
     */
    public function testRFC2253String(AttributeValue $value)
    {
        $this->assertIsString($value->rfc2253String());
    }

    /**
     * @depends testCreate
     */
    public function testToString(AttributeValue $value)
    {
        $this->assertIsString(strval($value));
    }
}
