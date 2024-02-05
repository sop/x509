<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group general-name
 *
 * @internal
 */
class GeneralNamesTest extends TestCase
{
    public function testCreate()
    {
        $gns = new GeneralNames(new DNSName('test1'), new DNSName('test2'));
        $this->assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(GeneralNames $gns)
    {
        $seq = $gns->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $gns = GeneralNames::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(GeneralNames $ref, GeneralNames $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testHas(GeneralNames $gns)
    {
        $this->assertTrue($gns->has(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends testCreate
     */
    public function testHasNot(GeneralNames $gns)
    {
        $this->assertFalse($gns->has(GeneralName::TAG_URI));
    }

    /**
     * @depends testCreate
     */
    public function testAllOf(GeneralNames $gns)
    {
        $this->assertCount(2, $gns->allOf(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends testCreate
     */
    public function testFirstOf(GeneralNames $gns)
    {
        $this->assertInstanceOf(DNSName::class,
            $gns->firstOf(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends testCreate
     */
    public function testFirstOfFail(GeneralNames $gns)
    {
        $this->expectException(UnexpectedValueException::class);
        $gns->firstOf(GeneralName::TAG_URI);
    }

    /**
     * @depends testCreate
     */
    public function testCount(GeneralNames $gns)
    {
        $this->assertCount(2, $gns);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(GeneralNames $gns)
    {
        $values = [];
        foreach ($gns as $gn) {
            $values[] = $gn;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(GeneralName::class, $values);
    }

    public function testFromEmptyFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralNames::fromASN1(new Sequence());
    }

    public function testEmptyToASN1Fail()
    {
        $gn = new GeneralNames();
        $this->expectException(LogicException::class);
        $gn->toASN1();
    }

    public function testFirstDNS()
    {
        $name = new DNSName('example.com');
        $gn = new GeneralNames($name);
        $this->assertEquals($name, $gn->firstDNS());
    }

    public function testFirstDN()
    {
        $name = DirectoryName::fromDNString('cn=Example');
        $gn = new GeneralNames($name);
        $this->assertEquals($name->dn(), $gn->firstDN());
    }

    public function testFirstURI()
    {
        $name = new UniformResourceIdentifier('urn:example');
        $gn = new GeneralNames($name);
        $this->assertEquals($name, $gn->firstURI());
    }

    public function testFirstDNSFail()
    {
        $gn = new GeneralNames(
            new GeneralNamesTest_NameMockup(GeneralName::TAG_DNS_NAME));
        $this->expectException(RuntimeException::class);
        $gn->firstDNS();
    }

    public function testFirstDNFail()
    {
        $gn = new GeneralNames(
            new GeneralNamesTest_NameMockup(GeneralName::TAG_DIRECTORY_NAME));
        $this->expectException(RuntimeException::class);
        $gn->firstDN();
    }

    public function testFirstURIFail()
    {
        $gn = new GeneralNames(
            new GeneralNamesTest_NameMockup(GeneralName::TAG_URI));
        $this->expectException(RuntimeException::class);
        $gn->firstURI();
    }
}

class GeneralNamesTest_NameMockup extends GeneralName
{
    public function __construct($tag)
    {
        $this->_tag = $tag;
    }

    public function string(): string
    {
        return '';
    }

    protected function _choiceASN1(): TaggedType
    {
        return new NullType();
    }
}
