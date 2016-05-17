<?php

use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\GeneralName;
use X509\GeneralName\IPAddress;


/**
 * @group general-name
 */
class IPAddressNameTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidASN1() {
		$el = new ImplicitlyTaggedType(GeneralName::TAG_IP_ADDRESS, 
			new OctetString(""));
		IPAddress::fromASN1($el);
	}
}
