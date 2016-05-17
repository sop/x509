<?php

use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\GeneralName;


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
}
