<?php

use X509\CertificationPath\Policy\PolicyNode;


/**
 * @group certification-path
 */
class PolicyNodeTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$node = new PolicyNode("1.3.6.1.3", array(), array());
		$this->assertInstanceOf(PolicyNode::class, $node);
	}
}
