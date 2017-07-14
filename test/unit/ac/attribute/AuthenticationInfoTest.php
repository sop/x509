<?php
use ASN1\Type\Constructed\Sequence;
use X501\ASN1\AttributeValue\AttributeValue;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Attribute\AuthenticationInfoAttributeValue;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 * @group attribute
 */
class AuthenticationInfoAttributeTest extends PHPUnit_Framework_TestCase
{
    const SERVICE_URI = "urn:service";
    
    const IDENT_URI = "urn:username";
    
    const AUTH_INFO = "password";
    
    public function testCreate()
    {
        $value = new AuthenticationInfoAttributeValue(
            new UniformResourceIdentifier(self::SERVICE_URI),
            new UniformResourceIdentifier(self::IDENT_URI), self::AUTH_INFO);
        $this->assertInstanceOf(AuthenticationInfoAttributeValue::class, $value);
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
        $value = AuthenticationInfoAttributeValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(AuthenticationInfoAttributeValue::class, $value);
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
        $this->assertEquals(AuthenticationInfoAttributeValue::OID, $value->oid());
    }
    
    /**
     * @depends testCreate
     *
     * @param AuthenticationInfoAttributeValue $value
     */
    public function testService(AuthenticationInfoAttributeValue $value)
    {
        $this->assertEquals(self::SERVICE_URI, $value->service());
    }
    
    /**
     * @depends testCreate
     *
     * @param AuthenticationInfoAttributeValue $value
     */
    public function testIdent(AuthenticationInfoAttributeValue $value)
    {
        $this->assertEquals(self::IDENT_URI, $value->ident());
    }
    
    /**
     * @depends testCreate
     *
     * @param AuthenticationInfoAttributeValue $value
     */
    public function testAuthInfo(AuthenticationInfoAttributeValue $value)
    {
        $this->assertEquals(self::AUTH_INFO, $value->authInfo());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeValue $value
     */
    public function testAttributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasAuthenticationInformation());
        return $attribs;
    }
    
    /**
     * @depends testAttributes
     *
     * @param Attributes $attribs
     */
    public function testFromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(AuthenticationInfoAttributeValue::class,
            $attribs->authenticationInformation());
    }
}
