<?php

use CryptoUtil\PEM\PEM;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathBuilding\CertificationPathBuilder;


/**
 * @group certification-path
 */
class CertificationPathBuildingTest extends PHPUnit_Framework_TestCase
{
	private static $_ca;
	
	private static $_interm;
	
	private static $_cert;
	
	public static function setUpBeforeClass() {
		self::$_ca = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
		self::$_interm = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-interm-rsa.pem"));
		self::$_cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_ca = null;
		self::$_interm = null;
		self::$_cert = null;
	}
	
	public function testBuildPath() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca));
		$path = $builder->shortestPathToTarget(self::$_cert, 
			new CertificateBundle(self::$_interm));
		$this->assertInstanceOf(CertificationPath::class, $path);
		return $path;
	}
	
	/**
	 * @depends testBuildPath
	 *
	 * @param CertificationPath $path
	 */
	public function testPathLength(CertificationPath $path) {
		$this->assertCount(3, $path);
	}
	
	/**
	 * @depends testBuildPath
	 *
	 * @param CertificationPath $path
	 */
	public function testPathAnchor(CertificationPath $path) {
		$this->assertEquals(self::$_ca, $path->certificates()[0]);
	}
	
	/**
	 * @depends testBuildPath
	 *
	 * @param CertificationPath $path
	 */
	public function testPathIntermediate(CertificationPath $path) {
		$this->assertEquals(self::$_interm, $path->certificates()[1]);
	}
	
	/**
	 * @depends testBuildPath
	 *
	 * @param CertificationPath $path
	 */
	public function testPathTarget(CertificationPath $path) {
		$this->assertEquals(self::$_cert, $path->certificates()[2]);
	}
	
	/**
	 * @expectedException X509\CertificationPath\Exception\PathBuildingException
	 */
	public function testBuildPathFail() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca));
		$builder->shortestPathToTarget(self::$_cert, new CertificateBundle());
	}
	
	public function testBuildSelfSigned() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca));
		$path = $builder->shortestPathToTarget(self::$_ca);
		$this->assertCount(1, $path);
	}
	
	public function testBuildLength2() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca));
		$path = $builder->shortestPathToTarget(self::$_interm);
		$this->assertCount(2, $path);
	}
	
	public function testBuildWithCAInIntermediate() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca));
		$path = $builder->shortestPathToTarget(self::$_cert, 
			new CertificateBundle(self::$_ca, self::$_interm));
		$this->assertCount(3, $path);
	}
	
	public function testBuildMultipleChoices() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca, self::$_interm));
		$paths = $builder->allPathsToTarget(self::$_cert, 
			new CertificateBundle(self::$_interm));
		$this->assertCount(2, $paths);
		$this->assertContainsOnlyInstancesOf(CertificationPath::class, $paths);
	}
	
	public function testBuildShortest() {
		$builder = new CertificationPathBuilder(
			new CertificateBundle(self::$_ca, self::$_interm));
		$path = $builder->shortestPathToTarget(self::$_cert, 
			new CertificateBundle(self::$_interm));
		$this->assertCount(2, $path);
	}
}
