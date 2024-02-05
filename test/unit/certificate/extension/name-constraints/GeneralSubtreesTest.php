<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group name-constraint
 *
 * @internal
 */
class GeneralSubtreesTest extends TestCase
{
    public function testCreate()
    {
        $subtrees = new GeneralSubtrees(
            new GeneralSubtree(new UniformResourceIdentifier('.example.com')),
            new GeneralSubtree(DirectoryName::fromDNString('cn=Test')));
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends testCreate
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
     */
    public function testRecoded(GeneralSubtrees $ref, GeneralSubtrees $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testAll(GeneralSubtrees $subtrees)
    {
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class,
            $subtrees->all());
    }

    /**
     * @depends testCreate
     */
    public function testCount(GeneralSubtrees $subtrees)
    {
        $this->assertCount(2, $subtrees);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(GeneralSubtrees $subtrees)
    {
        $values = [];
        foreach ($subtrees as $subtree) {
            $values[] = $subtree;
        }
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }

    public function testDecodeEmptyFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralSubtrees::fromASN1(new Sequence());
    }

    public function testEncodeEmptyFail()
    {
        $subtrees = new GeneralSubtrees();
        $this->expectException(LogicException::class);
        $subtrees->toASN1();
    }
}
