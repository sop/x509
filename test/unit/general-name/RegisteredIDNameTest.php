<?php
use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Tagged\ImplicitTagging;
use X509\GeneralName\GeneralName;
use X509\GeneralName\RegisteredID;

/**
 * @group general-name
 */
class RegisteredIDNameTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $rid = new RegisteredID("1.3.6.1.3.1");
        $this->assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }
    
    /**
     * @depends testCreate
     *
     * @param RegisteredID $rid
     */
    public function testEncode(RegisteredID $rid)
    {
        $el = $rid->toASN1();
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
        $this->assertEquals(GeneralName::TAG_REGISTERED_ID, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $rid = RegisteredID::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param RegisteredID $ref
     * @param RegisteredID $new
     */
    public function testRecoded(RegisteredID $ref, RegisteredID $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param RegisteredID $rid
     */
    public function testString(RegisteredID $rid)
    {
        $this->assertInternalType("string", $rid->string());
    }
    
    /**
     * @depends testCreate
     *
     * @param RegisteredID $rid
     */
    public function testOID(RegisteredID $rid)
    {
        $this->assertEquals("1.3.6.1.3.1", $rid->oid());
    }
}
