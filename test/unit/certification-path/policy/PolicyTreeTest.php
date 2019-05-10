<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\X509\CertificationPath\Policy\PolicyNode;
use Sop\X509\CertificationPath\Policy\PolicyTree;

/**
 * @group certification-path
 *
 * @internal
 */
class PolicyTreeTest extends TestCase
{
    /**
     * Cover edge case where root node is pruned.
     */
    public function testNodesAtDepthNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('_root');
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $this->assertEmpty($tree->policiesAtDepth(1));
    }

    /**
     * Cover edge case where root node is pruned.
     */
    public function testValidPolicyNodeSetNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('_root');
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod('_validPolicyNodeSet');
        $mtd->setAccessible(true);
        $this->assertEmpty($mtd->invoke($tree));
    }

    /**
     * Cover edge case where root node is pruned.
     */
    public function testPruneNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('_root');
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod('_pruneTree');
        $mtd->setAccessible(true);
        $this->assertEquals(0, $mtd->invoke($tree, 0));
    }
}
