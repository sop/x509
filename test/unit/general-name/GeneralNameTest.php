<?php

use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\UnspecifiedType;
use X509\GeneralName\DNSName;
use X509\GeneralName\GeneralName;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group general-name
 */
class GeneralNameTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidTagFail() {
		GeneralName::fromASN1(new ImplicitlyTaggedType(9, new NullType()));
	}
	
	/**
	 * @expectedException BadMethodCallException
	 */
	public function testFromChosenBadCall() {
		GeneralName::fromChosenASN1(new UnspecifiedType(new NullType()));
	}
	
	public function testEquals() {
		$n1 = new UniformResourceIdentifier("urn:1");
		$n2 = new UniformResourceIdentifier("urn:1");
		$this->assertTrue($n1->equals($n2));
	}
	
	public function testNotEquals() {
		$n1 = new UniformResourceIdentifier("urn:1");
		$n2 = new UniformResourceIdentifier("urn:2");
		$this->assertFalse($n1->equals($n2));
	}
	
	public function testNotEqualsDifferentTypes() {
		$n1 = new UniformResourceIdentifier("urn:1");
		$n2 = new DNSName("test");
		$this->assertFalse($n1->equals($n2));
	}
}
