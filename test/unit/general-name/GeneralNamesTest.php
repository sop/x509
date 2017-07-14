<?php
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\NullType;
use X509\GeneralName\DNSName;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group general-name
 */
class GeneralNamesTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $gns = new GeneralNames(new DNSName("test1"), new DNSName("test2"));
        $this->assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
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
     *
     * @param GeneralNames $ref
     * @param GeneralNames $new
     */
    public function testRecoded(GeneralNames $ref, GeneralNames $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
     */
    public function testHas(GeneralNames $gns)
    {
        $this->assertTrue($gns->has(GeneralName::TAG_DNS_NAME));
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
     */
    public function testHasNot(GeneralNames $gns)
    {
        $this->assertFalse($gns->has(GeneralName::TAG_URI));
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
     */
    public function testAllOf(GeneralNames $gns)
    {
        $this->assertCount(2, $gns->allOf(GeneralName::TAG_DNS_NAME));
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
     */
    public function testFirstOf(GeneralNames $gns)
    {
        $this->assertInstanceOf(DNSName::class,
            $gns->firstOf(GeneralName::TAG_DNS_NAME));
    }
    
    /**
     * @depends testCreate
     * @expectedException UnexpectedValueException
     *
     * @param GeneralNames $gns
     */
    public function testFirstOfFail(GeneralNames $gns)
    {
        $gns->firstOf(GeneralName::TAG_URI);
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
     */
    public function testCount(GeneralNames $gns)
    {
        $this->assertCount(2, $gns);
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralNames $gns
     */
    public function testIterator(GeneralNames $gns)
    {
        $values = array();
        foreach ($gns as $gn) {
            $values[] = $gn;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(GeneralName::class, $values);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromEmptyFail()
    {
        GeneralNames::fromASN1(new Sequence());
    }
    
    /**
     * @expectedException LogicException
     */
    public function testEmptyToASN1Fail()
    {
        $gn = new GeneralNames();
        $gn->toASN1();
    }
    
    public function testFirstDNS()
    {
        $name = new DNSName("example.com");
        $gn = new GeneralNames($name);
        $this->assertEquals($name, $gn->firstDNS());
    }
    
    public function testFirstDN()
    {
        $name = DirectoryName::fromDNString("cn=Example");
        $gn = new GeneralNames($name);
        $this->assertEquals($name->dn(), $gn->firstDN());
    }
    
    public function testFirstURI()
    {
        $name = new UniformResourceIdentifier("urn:example");
        $gn = new GeneralNames($name);
        $this->assertEquals($name, $gn->firstURI());
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testFirstDNSFail()
    {
        $gn = new GeneralNames(
            new GeneralNamesTest_NameMockup(GeneralName::TAG_DNS_NAME));
        $gn->firstDNS();
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testFirstDNFail()
    {
        $gn = new GeneralNames(
            new GeneralNamesTest_NameMockup(GeneralName::TAG_DIRECTORY_NAME));
        $gn->firstDN();
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testFirstURIFail()
    {
        $gn = new GeneralNames(
            new GeneralNamesTest_NameMockup(GeneralName::TAG_URI));
        $gn->firstURI();
    }
}

class GeneralNamesTest_NameMockup extends GeneralName
{
    public function __construct($tag)
    {
        $this->_tag = $tag;
    }
    public function string()
    {
        return "";
    }
    protected function _choiceASN1()
    {
        return new NullType();
    }
}
