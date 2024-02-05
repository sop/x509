<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 * @group attribute
 *
 * @internal
 */
class AccessIdentityAttributeTest extends TestCase
{
    public const SERVICE_URI = 'urn:service';

    public const IDENT_URI = 'urn:username';

    public function testCreate()
    {
        $value = new AccessIdentityAttributeValue(
            new UniformResourceIdentifier(self::SERVICE_URI),
            new UniformResourceIdentifier(self::IDENT_URI));
        $this->assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        $value = AccessIdentityAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        $this->assertEquals(AccessIdentityAttributeValue::OID, $value->oid());
    }

    /**
     * @depends testCreate
     */
    public function testService(AccessIdentityAttributeValue $value)
    {
        $this->assertEquals(self::SERVICE_URI, $value->service());
    }

    /**
     * @depends testCreate
     */
    public function testIdent(AccessIdentityAttributeValue $value)
    {
        $this->assertEquals(self::IDENT_URI, $value->ident());
    }

    /**
     * @depends testCreate
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasAccessIdentity());
        return $attribs;
    }

    /**
     * @depends testAttributes
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(AccessIdentityAttributeValue::class,
            $attribs->accessIdentity());
    }
}
