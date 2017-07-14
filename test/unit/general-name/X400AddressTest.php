<?php
use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitTagging;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\GeneralName;
use X509\GeneralName\X400Address;

/**
 * @group general-name
 */
class X400AddressTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $name = X400Address::fromASN1(
            new ImplicitlyTaggedType(GeneralName::TAG_X400_ADDRESS,
                new Sequence()));
        $this->assertInstanceOf(X400Address::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     *
     * @param X400Address $name
     */
    public function testEncode(X400Address $name)
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
        $this->assertEquals(GeneralName::TAG_X400_ADDRESS, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = X400Address::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(X400Address::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param X400Address $ref
     * @param X400Address $new
     */
    public function testRecoded(X400Address $ref, X400Address $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param X400Address $name
     */
    public function testString(X400Address $name)
    {
        $this->assertInternalType("string", $name->string());
    }
}
