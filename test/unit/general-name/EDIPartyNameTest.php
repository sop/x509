<?php
use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitTagging;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\EDIPartyName;
use X509\GeneralName\GeneralName;

/**
 * @group general-name
 */
class EDIPartyNameTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $name = EDIPartyName::fromASN1(
            new ImplicitlyTaggedType(GeneralName::TAG_EDI_PARTY_NAME,
                new Sequence()));
        $this->assertInstanceOf(EDIPartyName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     *
     * @param EDIPartyName $name
     */
    public function testEncode(EDIPartyName $name)
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
        $this->assertEquals(GeneralName::TAG_EDI_PARTY_NAME, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = EDIPartyName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(EDIPartyName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param EDIPartyName $ref
     * @param EDIPartyName $new
     */
    public function testRecoded(EDIPartyName $ref, EDIPartyName $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param EDIPartyName $name
     */
    public function testString(EDIPartyName $name)
    {
        $this->assertInternalType("string", $name->string());
    }
}
