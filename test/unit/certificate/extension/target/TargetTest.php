<?php

use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\Certificate\Extension\Target\Target;
use X509\Certificate\Extension\Target\TargetGroup;
use X509\Certificate\Extension\Target\TargetName;
use X509\GeneralName\DNSName;
use X509\GeneralName\RFC822Name;


/**
 * @group certificate
 * @group extension
 * @group target
 */
class TargetTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException BadMethodCallException
	 */
	public function testFromASN1BadCall() {
		Target::fromChosenASN1(new ImplicitlyTaggedType(0, new NullType()));
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDecodeTargetCertUnsupportedFail() {
		Target::fromASN1(
			new ImplicitlyTaggedType(Target::TYPE_CERT, new NullType()));
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testDecodeUnsupportedTagFail() {
		Target::fromASN1(new ImplicitlyTaggedType(3, new NullType()));
	}
	
	public function testEquals() {
		$t1 = new TargetName(new DNSName("n1"));
		$t2 = new TargetName(new DNSName("n1"));
		$this->assertTrue($t1->equals($t2));
	}
	
	public function testNotEquals() {
		$t1 = new TargetName(new DNSName("n1"));
		$t2 = new TargetName(new DNSName("n2"));
		$this->assertFalse($t1->equals($t2));
	}
	
	public function testNotEqualsDifferentEncoding() {
		$t1 = new TargetName(new DNSName("n1"));
		$t2 = new TargetName(new RFC822Name("n2"));
		$this->assertFalse($t1->equals($t2));
	}
	
	public function testNotEqualsDifferentType() {
		$t1 = new TargetName(new DNSName("n1"));
		$t2 = new TargetGroup(new DNSName("n1"));
		$this->assertFalse($t1->equals($t2));
	}
}
