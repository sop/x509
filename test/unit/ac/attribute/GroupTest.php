<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group ac
 * @group attribute
 *
 * @internal
 */
class GroupAttributeTest extends TestCase
{
    const AUTHORITY_DN = 'cn=Authority Name';

    const GROUP_NAME = 'administrators';

    public function testCreate()
    {
        $value = new GroupAttributeValue(
            IetfAttrValue::fromString(self::GROUP_NAME));
        $value = $value->withPolicyAuthority(
            new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN)));
        $this->assertInstanceOf(GroupAttributeValue::class, $value);
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
        $value = GroupAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(GroupAttributeValue::class, $value);
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
        $this->assertEquals(GroupAttributeValue::OID, $value->oid());
    }

    /**
     * @depends testCreate
     *
     * @param GroupAttributeValue $value
     */
    public function testAuthority(GroupAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN,
            $value->policyAuthority()
                ->firstDN());
    }

    /**
     * @depends testCreate
     *
     * @param GroupAttributeValue $value
     */
    public function testCount(GroupAttributeValue $value)
    {
        $this->assertCount(1, $value);
    }

    /**
     * @depends testCreate
     *
     * @param GroupAttributeValue $value
     */
    public function testGroupName(GroupAttributeValue $value)
    {
        $this->assertEquals(self::GROUP_NAME, $value->first());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasGroup());
        return $attribs;
    }

    /**
     * @depends testAttributes
     *
     * @param Attributes $attribs
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(GroupAttributeValue::class, $attribs->group());
    }
}
