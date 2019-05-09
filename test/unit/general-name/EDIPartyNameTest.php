<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\EDIPartyName;
use Sop\X509\GeneralName\GeneralName;

/**
 * @group general-name
 *
 * @internal
 */
class EDIPartyNameTest extends TestCase
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
        $this->assertIsString($name->string());
    }
}
