<?php

use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\KeyUsageExtension;
use X509\Certificate\Extensions;

require_once __DIR__ . "/RefExtTestHelper.php";


/**
 * @group certificate
 * @group extension
 * @group decode
 */
class RefKeyUsageTest extends RefExtTestHelper
{
	/**
	 *
	 * @param Extensions $extensions
	 * @return KeyUsageExtension
	 */
	public function testKeyUsage() {
		$ext = self::$_extensions->get(Extension::OID_KEY_USAGE);
		$this->assertInstanceOf(KeyUsageExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testKeyUsage
	 *
	 * @param KeyUsageExtension $ku
	 */
	public function testKeyUsageBits(KeyUsageExtension $ku) {
		$this->assertFalse($ku->isDigitalSignature());
		$this->assertFalse($ku->isNonRepudiation());
		$this->assertTrue($ku->isKeyEncipherment());
		$this->assertFalse($ku->isDataEncipherment());
		$this->assertFalse($ku->isKeyAgreement());
		$this->assertTrue($ku->isKeyCertSign());
		$this->assertFalse($ku->isCRLSign());
		$this->assertFalse($ku->isEncipherOnly());
		$this->assertFalse($ku->isDecipherOnly());
	}
}
