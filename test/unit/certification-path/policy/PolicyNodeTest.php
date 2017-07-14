<?php
use X509\CertificationPath\Policy\PolicyNode;

/**
 * @group certification-path
 */
class PolicyNodeTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $node = new PolicyNode("1.3.6.1.3", array(), array());
        $this->assertInstanceOf(PolicyNode::class, $node);
    }
    
    public function testHasChildWithPolicyMatch()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(
            new PolicyNode("1.3.6.1.3", [], []));
        $this->assertTrue($node->hasChildWithValidPolicy("1.3.6.1.3"));
    }
    
    public function testParent()
    {
        $root = PolicyNode::anyPolicyNode();
        $child = new PolicyNode("1.3.6.1.3", [], []);
        $root->addChild($child);
        $this->assertEquals($root, $child->parent());
    }
    
    public function testIterator()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(
            PolicyNode::anyPolicyNode())->addChild(PolicyNode::anyPolicyNode());
        $nodes = array();
        foreach ($node as $child) {
            $nodes[] = $child;
        }
        $this->assertContainsOnlyInstancesOf(PolicyNode::class, $nodes);
    }
}
