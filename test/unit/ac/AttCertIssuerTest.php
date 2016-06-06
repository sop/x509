<?php

use ASN1\Type\Primitive\NullType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\AttributeCertificate\AttCertIssuer;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;


/**
 * @group ac
 */
class AttCertIssuerTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testV1FormFail() {
		$v1 = new GeneralNames(DirectoryName::fromDNString("cn=Test"));
		AttCertIssuer::fromASN1($v1->toASN1()->asUnspecified());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedType() {
		$el = new ImplicitlyTaggedType(1, new NullType());
		AttCertIssuer::fromASN1($el->asUnspecified());
	}
}
