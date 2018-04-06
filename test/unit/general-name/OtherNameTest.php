<?php

declare(strict_types=1);

use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitTagging;
use X509\GeneralName\GeneralName;
use X509\GeneralName\OtherName;

/**
 * @group general-name
 */
class OtherNameTest extends \PHPUnit\Framework\TestCase
{
    public function testCreate()
    {
        $name = new OtherName("1.3.6.1.3.1", new NullType());
        $this->assertInstanceOf(OtherName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     *
     * @param OtherName $name
     */
    public function testEncode(OtherName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testChoiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        $this->assertEquals(GeneralName::TAG_OTHER_NAME, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = OtherName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(OtherName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param OtherName $ref
     * @param OtherName $new
     */
    public function testRecoded(OtherName $ref, OtherName $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param OtherName $name
     */
    public function testString(OtherName $name)
    {
        $this->assertInternalType("string", $name->string());
    }
    
    /**
     * @depends testCreate
     *
     * @param OtherName $name
     */
    public function testOID(OtherName $name)
    {
        $this->assertEquals("1.3.6.1.3.1", $name->type());
    }
    
    /**
     * @depends testCreate
     *
     * @param OtherName $name
     */
    public function testValue(OtherName $name)
    {
        $this->assertEquals(new NullType(), $name->value());
    }
}
