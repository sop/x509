<?php

declare(strict_types=1);

use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Tagged\ImplicitTagging;
use X509\GeneralName\GeneralName;
use X509\GeneralName\RFC822Name;

/**
 * @group general-name
 */
class RFC822NameTest extends \PHPUnit\Framework\TestCase
{
    public function testCreate()
    {
        $name = new RFC822Name("test@example.com");
        $this->assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     *
     * @param RFC822Name $name
     */
    public function testEncode(RFC822Name $name)
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
        $this->assertEquals(GeneralName::TAG_RFC822_NAME, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = RFC822Name::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param RFC822Name $ref
     * @param RFC822Name $new
     */
    public function testRecoded(RFC822Name $ref, RFC822Name $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param RFC822Name $name
     */
    public function testString(RFC822Name $name)
    {
        $this->assertInternalType("string", $name->string());
    }
    
    /**
     * @depends testCreate
     *
     * @param RFC822Name $name
     */
    public function testEmail(RFC822Name $name)
    {
        $this->assertEquals("test@example.com", $name->email());
    }
}
