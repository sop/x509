<?php

use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathValidation\PathValidationConfig;
use X509\CertificationPath\PathValidation\PathValidationResult;


/**
 * @group certification-path
 */
class CertificationPathTest extends PHPUnit_Framework_TestCase
{
	private static $_certs;
	
	public static function setUpBeforeClass() {
		self::$_certs = array(
			Certificate::fromPEM(
				PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem")), 
			Certificate::fromPEM(
				PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-interm-rsa.pem")), 
			Certificate::fromPEM(
				PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem")));
	}
	
	public static function tearDownAfterClass() {
		self::$_certs = null;
	}
	
	public function testCreate() {
		$path = new CertificationPath(...self::$_certs);
		$this->assertInstanceOf(CertificationPath::class, $path);
		return $path;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationPath $path
	 */
	public function testCount(CertificationPath $path) {
		$this->assertCount(3, $path);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationPath $path
	 */
	public function testIterator(CertificationPath $path) {
		$values = array();
		foreach ($path as $cert) {
			$values[] = $cert;
		}
		$this->assertCount(3, $values);
		$this->assertContainsOnlyInstancesOf(Certificate::class, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificationPath $path
	 */
	public function testValidate(CertificationPath $path) {
		$result = $path->validate(Crypto::getDefault(), 
			PathValidationConfig::defaultConfig());
		$this->assertInstanceOf(PathValidationResult::class, $result);
	}
	
	public function testFromTrustAnchorToTarget() {
		$path = CertificationPath::fromTrustAnchorToTarget(self::$_certs[0], 
			self::$_certs[2], new CertificateBundle(...self::$_certs));
		$this->assertInstanceOf(CertificationPath::class, $path);
	}
}
