<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
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
class ChargingIdentityAttributeTest extends TestCase
{
    public const AUTHORITY_DN = 'cn=Authority Name';

    public const OCTETS_VAL = 'octet string';

    public const OID_VAL = '1.3.6.1.3.1';

    public const UTF8_VAL = 'UTF-8 string';

    public function testCreate()
    {
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
        $value = ChargingIdentityAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
        $this->assertEquals(ChargingIdentityAttributeValue::OID, $value->oid());
    }

    /**
     * @depends testCreate
     */
    public function testAuthority(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN,
            $value->policyAuthority()
                ->firstDN());
    }

    /**
     * @depends testCreate
     */
    public function testCount(ChargingIdentityAttributeValue $value)
    {
        $this->assertCount(3, $value);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(ChargingIdentityAttributeValue $value)
    {
        $values = [];
        foreach ($value as $val) {
            $values[] = $val;
        }
        $this->assertCount(3, $values);
        $this->assertContainsOnlyInstancesOf(IetfAttrValue::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testOctetStringValue(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::OCTETS_VAL, $value->values()[0]);
    }

    /**
     * @depends testCreate
     */
    public function testOIDValue(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::OID_VAL, $value->values()[1]);
    }

    /**
     * @depends testCreate
     */
    public function testUTF8Value(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::UTF8_VAL, $value->values()[2]);
    }

    /**
     * @depends testCreate
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasChargingIdentity());
        return $attribs;
    }

    /**
     * @depends testAttributes
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(ChargingIdentityAttributeValue::class,
            $attribs->chargingIdentity());
    }
}
