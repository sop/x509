<?php
use ASN1\Type\Constructed\Sequence;
use X501\ASN1\AttributeValue\AttributeValue;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 * @group attribute
 */
class AccessIdentityAttributeTest extends PHPUnit_Framework_TestCase
{
    const SERVICE_URI = "urn:service";
    
    const IDENT_URI = "urn:username";
    
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
        $value = AccessIdentityAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        $this->assertEquals(AccessIdentityAttributeValue::OID, $value->oid());
    }
    
    /**
     * @depends testCreate
     *
     * @param AccessIdentityAttributeValue $value
     */
    public function testService(AccessIdentityAttributeValue $value)
    {
        $this->assertEquals(self::SERVICE_URI, $value->service());
    }
    
    /**
     * @depends testCreate
     *
     * @param AccessIdentityAttributeValue $value
     */
    public function testIdent(AccessIdentityAttributeValue $value)
    {
        $this->assertEquals(self::IDENT_URI, $value->ident());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasAccessIdentity());
        return $attribs;
    }
    
    /**
     * @depends testAttributes
     *
     * @param Attributes $attribs
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(AccessIdentityAttributeValue::class,
            $attribs->accessIdentity());
    }
}
