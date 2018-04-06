<?php

declare(strict_types=1);

use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Tagged\ImplicitTagging;
use X509\GeneralName\DNSName;
use X509\GeneralName\GeneralName;

/**
 * @group general-name
 */
class DNSNameTest extends \PHPUnit\Framework\TestCase
{
    public function testCreate()
    {
        $name = new DNSName("test.example.com");
        $this->assertInstanceOf(DNSName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     *
     * @param DNSName $name
     */
    public function testEncode(DNSName $name)
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
        $this->assertEquals(GeneralName::TAG_DNS_NAME, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = DNSName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(DNSName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param DNSName $ref
     * @param DNSName $new
     */
    public function testRecoded(DNSName $ref, DNSName $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param DNSName $name
     */
    public function testDNS(DNSName $name)
    {
        $this->assertEquals("test.example.com", $name->name());
    }
}
