<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\RFC822Name;

/**
 * @group general-name
 *
 * @internal
 */
class RFC822NameTest extends TestCase
{
    public function testCreate()
    {
        $name = new RFC822Name('test@example.com');
        $this->assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
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
     */
    public function testRecoded(RFC822Name $ref, RFC822Name $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testString(RFC822Name $name)
    {
        $this->assertIsString($name->string());
    }

    /**
     * @depends testCreate
     */
    public function testEmail(RFC822Name $name)
    {
        $this->assertEquals('test@example.com', $name->email());
    }
}
