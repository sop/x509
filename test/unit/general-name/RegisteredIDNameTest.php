<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\RegisteredID;

/**
 * @group general-name
 *
 * @internal
 */
class RegisteredIDNameTest extends TestCase
{
    public function testCreate()
    {
        $rid = new RegisteredID('1.3.6.1.3.1');
        $this->assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }

    /**
     * @depends testCreate
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
     */
    public function testRecoded(RegisteredID $ref, RegisteredID $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testString(RegisteredID $rid)
    {
        $this->assertIsString($rid->string());
    }

    /**
     * @depends testCreate
     */
    public function testOID(RegisteredID $rid)
    {
        $this->assertEquals('1.3.6.1.3.1', $rid->oid());
    }
}
