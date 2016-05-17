<?php

use CryptoUtil\PEM\PEM;
use X509\AttributeCertificate\IssuerSerial;
use X509\Certificate\Certificate;


/**
 * @group ac
 */
class IssuerSerialIntegrationTest extends PHPUnit_Framework_TestCase
{
	private static $_cert;
	
	public static function setUpBeforeClass() {
		self::$_cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_cert = null;
	}
	
	public function testFromCertificate() {
		$is = IssuerSerial::fromCertificate(self::$_cert);
		$this->assertInstanceOf(IssuerSerial::class, $is);
		return $is;
	}
	
	/**
	 * @depends testFromCertificate
	 *
	 * @param IssuerSerial $is
	 */
	public function testIssuer(IssuerSerial $is) {
		$this->assertEquals(self::$_cert->tbsCertificate()
			->issuer(), $is->issuer()
			->firstDN());
	}
	
	/**
	 * @depends testFromCertificate
	 *
	 * @param IssuerSerial $is
	 */
	public function testSerial(IssuerSerial $is) {
		$this->assertEquals(self::$_cert->tbsCertificate()
			->serialNumber(), $is->serial());
	}
}
