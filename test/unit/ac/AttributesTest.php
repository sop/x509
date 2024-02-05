<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 * @group attribute
 *
 * @internal
 */
class AttributeCertificateAttributesTest extends TestCase
{
    public function testCreate()
    {
        $attribs = Attributes::fromAttributeValues(
            new AccessIdentityAttributeValue(
                new UniformResourceIdentifier('urn:service'),
                new UniformResourceIdentifier('urn:ident')),
            new RoleAttributeValue(new UniformResourceIdentifier('urn:admin')),
            new DescriptionValue('test'));
        $this->assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Attributes $attribs)
    {
        $seq = $attribs->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $tc = Attributes::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Attributes::class, $tc);
        return $tc;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Attributes $ref, Attributes $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testCount(Attributes $attribs)
    {
        $this->assertCount(3, $attribs);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(Attributes $attribs)
    {
        $values = [];
        foreach ($attribs as $attr) {
            $values[] = $attr;
        }
        $this->assertCount(3, $values);
        $this->assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testHas(Attributes $attribs)
    {
        $this->assertTrue($attribs->has(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends testCreate
     */
    public function testFirstOf(Attributes $attribs)
    {
        $this->assertInstanceOf(Attribute::class,
            $attribs->firstOf(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends testCreate
     */
    public function testAllOf(Attributes $attribs)
    {
        $this->assertCount(1, $attribs->allOf(
            AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends testCreate
     */
    public function testWithAdditional(Attributes $attribs)
    {
        $attribs = $attribs->withAdditional(
            Attribute::fromAttributeValues(
                new GroupAttributeValue(IetfAttrValue::fromString('test'))));
        $this->assertInstanceOf(Attributes::class, $attribs);
    }

    /**
     * @depends testCreate
     */
    public function testWithUniqueReplace(Attributes $attribs)
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(
                new RoleAttributeValue(new UniformResourceIdentifier('uri:new'))));
        $this->assertInstanceOf(Attributes::class, $attribs);
        $this->assertCount(3, $attribs);
        $this->assertEquals('uri:new',
            $attribs->firstOf(AttributeType::OID_ROLE)
                ->first()
                ->roleName());
    }

    /**
     * @depends testCreate
     */
    public function testWithUniqueAdded(Attributes $attribs)
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(
                new GroupAttributeValue(IetfAttrValue::fromString('test'))));
        $this->assertCount(4, $attribs);
    }
}
