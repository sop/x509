<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\X509\CertificationPath\Policy\PolicyNode;

/**
 * @group certification-path
 *
 * @internal
 */
class PolicyNodeTest extends TestCase
{
    public function testCreate()
    {
        $node = new PolicyNode('1.3.6.1.3', [], []);
        $this->assertInstanceOf(PolicyNode::class, $node);
    }

    public function testHasChildWithPolicyMatch()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(
            new PolicyNode('1.3.6.1.3', [], []));
        $this->assertTrue($node->hasChildWithValidPolicy('1.3.6.1.3'));
    }

    public function testParent()
    {
        $root = PolicyNode::anyPolicyNode();
        $child = new PolicyNode('1.3.6.1.3', [], []);
        $root->addChild($child);
        $this->assertEquals($root, $child->parent());
    }

    public function testIterator()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(
            PolicyNode::anyPolicyNode())->addChild(PolicyNode::anyPolicyNode());
        $nodes = [];
        foreach ($node as $child) {
            $nodes[] = $child;
        }
        $this->assertContainsOnlyInstancesOf(PolicyNode::class, $nodes);
    }
}
