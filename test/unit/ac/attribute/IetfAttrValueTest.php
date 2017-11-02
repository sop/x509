<?php

declare(strict_types=1);

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\NullType;
use X509\AttributeCertificate\Attribute\IetfAttrValue;

/**
 * @group ac
 * @group attribute
 */
class IetfAttrValueTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromUnsupportedTypeFail()
    {
        IetfAttrValue::fromASN1(new UnspecifiedType(new NullType()));
    }
    
    /**
     * @expectedException LogicException
     */
    public function testToUnsupportedTypeFail()
    {
        $val = new IetfAttrValue("", Element::TYPE_NULL);
        $val->toASN1();
    }
    
    public function testCreateOctetString()
    {
        $val = IetfAttrValue::fromOctets("test");
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }
    
    /**
     * @depends testCreateOctetString
     *
     * @param IetfAttrValue $val
     */
    public function testOctetStringType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_OCTET_STRING, $val->type());
    }
    
    /**
     * @depends testCreateOctetString
     *
     * @param IetfAttrValue $val
     */
    public function testIsOctetString(IetfAttrValue $val)
    {
        $this->assertTrue($val->isOctets());
    }
    
    /**
     * @depends testCreateOctetString
     *
     * @param IetfAttrValue $val
     */
    public function testValue(IetfAttrValue $val)
    {
        $this->assertEquals("test", $val->value());
    }
    
    public function testCreateUTF8String()
    {
        $val = IetfAttrValue::fromString("test");
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }
    
    /**
     * @depends testCreateUTF8String
     *
     * @param IetfAttrValue $val
     */
    public function testUTF8StringType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_UTF8_STRING, $val->type());
    }
    
    /**
     * @depends testCreateUTF8String
     *
     * @param IetfAttrValue $val
     */
    public function testIsUTF8String(IetfAttrValue $val)
    {
        $this->assertTrue($val->isString());
    }
    
    public function testCreateOID()
    {
        $val = IetfAttrValue::fromOID("1.3.6.1.3");
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }
    
    /**
     * @depends testCreateOID
     *
     * @param IetfAttrValue $val
     */
    public function testOIDType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_OBJECT_IDENTIFIER, $val->type());
    }
    
    /**
     * @depends testCreateOID
     *
     * @param IetfAttrValue $val
     */
    public function testIsOID(IetfAttrValue $val)
    {
        $this->assertTrue($val->isOID());
    }
}
