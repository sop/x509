<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X501\ASN1\Name;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralName;

/**
 * @group general-name
 *
 * @internal
 */
class DirectoryNameTest extends TestCase
{
    public function testCreate()
    {
        $name = DirectoryName::fromDNString('cn=Test');
        $this->assertInstanceOf(DirectoryName::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     *
     * @param DirectoryName $name
     */
    public function testEncode(DirectoryName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ExplicitTagging::class, $el);
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
        $this->assertEquals(GeneralName::TAG_DIRECTORY_NAME, $el->tag());
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = DirectoryName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(DirectoryName::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param DirectoryName $ref
     * @param DirectoryName $new
     */
    public function testRecoded(DirectoryName $ref, DirectoryName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param DirectoryName $name
     */
    public function testString(DirectoryName $name)
    {
        $this->assertEquals('cn=Test', $name->string());
    }

    /**
     * @depends testCreate
     *
     * @param DirectoryName $name
     */
    public function testDN(DirectoryName $name)
    {
        $this->assertEquals(Name::fromString('cn=Test'), $name->dn());
    }
}
