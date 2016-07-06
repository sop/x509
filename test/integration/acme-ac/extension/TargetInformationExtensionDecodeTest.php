<?php

use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\Target\Target;
use X509\Certificate\Extension\TargetInformationExtension;

require_once __DIR__ . "/RefACExtTestHelper.php";


/**
 * @group ac
 * @group decode
 * @group extension
 */
class TargetInformationExtensionDecodeTest extends RefACExtTestHelper
{
	public function testExtension() {
		$ext = self::$_extensions->get(Extension::OID_TARGET_INFORMATION);
		$this->assertInstanceOf(TargetInformationExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testExtension
	 *
	 * @param TargetInformationExtension $ti
	 */
	public function testCount(TargetInformationExtension $ti) {
		$targets = $ti->targets();
		$this->assertCount(3, $targets);
	}
	
	/**
	 * @depends testExtension
	 *
	 * @param TargetInformationExtension $ti
	 */
	public function testValues(TargetInformationExtension $ti) {
		$vals = array_map(
			function (Target $target) {
				return $target->string();
			}, $ti->targets()->all());
		$this->assertEquals(array("urn:test", "*.example.com", "urn:another"), 
			$vals, "", 0.0, 10, true);
	}
}
