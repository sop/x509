<?php

declare(strict_types=1);

use X509\CertificationPath\Policy\PolicyNode;
use X509\CertificationPath\Policy\PolicyTree;

/**
 * @group certification-path
 */
class PolicyTreeTest extends PHPUnit_Framework_TestCase
{
    /**
     * Cover edge case where root node is pruned.
     */
    public function testNodesAtDepthNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty("_root");
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
        $prop = $obj->getProperty("_root");
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod("_validPolicyNodeSet");
        $mtd->setAccessible(true);
        $this->assertEmpty($mtd->invoke($tree));
    }
}
