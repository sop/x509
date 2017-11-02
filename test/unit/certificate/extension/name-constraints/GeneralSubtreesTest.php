<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group name-constraint
 */
class GeneralSubtreesTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $subtrees = new GeneralSubtrees(
            new GeneralSubtree(new UniformResourceIdentifier(".example.com")),
            new GeneralSubtree(DirectoryName::fromDNString("cn=Test")));
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralSubtrees $subtrees
     */
    public function testEncode(GeneralSubtrees $subtrees)
    {
        $el = $subtrees->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $subtrees = GeneralSubtrees::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param GeneralSubtrees $ref
     * @param GeneralSubtrees $new
     */
    public function testRecoded(GeneralSubtrees $ref, GeneralSubtrees $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralSubtrees $subtrees
     */
    public function testAll(GeneralSubtrees $subtrees)
    {
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class,
            $subtrees->all());
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralSubtrees $subtrees
     */
    public function testCount(GeneralSubtrees $subtrees)
    {
        $this->assertCount(2, $subtrees);
    }
    
    /**
     * @depends testCreate
     *
     * @param GeneralSubtrees $subtrees
     */
    public function testIterator(GeneralSubtrees $subtrees)
    {
        $values = array();
        foreach ($subtrees as $subtree) {
            $values[] = $subtree;
        }
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testDecodeEmptyFail()
    {
        GeneralSubtrees::fromASN1(new Sequence());
    }
    
    /**
     * @expectedException LogicException
     */
    public function testEncodeEmptyFail()
    {
        $subtrees = new GeneralSubtrees();
        $subtrees->toASN1();
    }
}
