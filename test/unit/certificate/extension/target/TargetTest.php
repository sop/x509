<?php

use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\Certificate\Extension\Target\Target;


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
		$cls = new ReflectionClass(Target::class);
		$mtd = $cls->getMethod("_fromASN1");
		$mtd->setAccessible(true);
		$mtd->invoke(null, new ImplicitlyTaggedType(0, new NullType()));
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
}
