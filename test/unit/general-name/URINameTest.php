<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group general-name
 *
 * @internal
 */
class URINameTest extends TestCase
{
    public const URI = 'urn:test';

    public function testCreate()
    {
        $uri = new UniformResourceIdentifier(self::URI);
        $this->assertInstanceOf(UniformResourceIdentifier::class, $uri);
        return $uri;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(UniformResourceIdentifier $uri)
    {
        $el = $uri->toASN1();
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
        $this->assertEquals(GeneralName::TAG_URI, $el->tag());
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $uri = UniformResourceIdentifier::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(UniformResourceIdentifier::class, $uri);
        return $uri;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(UniformResourceIdentifier $ref,
        UniformResourceIdentifier $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testString(UniformResourceIdentifier $uri)
    {
        $this->assertEquals(self::URI, $uri->string());
    }

    /**
     * @depends testCreate
     */
    public function testURI(UniformResourceIdentifier $uri)
    {
        $this->assertEquals(self::URI, $uri->uri());
    }
}
