<?php

use CryptoUtil\PEM\PEM;
use CryptoUtil\PEM\PEMBundle;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\CertificationPath\CertificationPath;
use X509\CertificationPath\PathBuilding\CertificationPathBuilder;


/**
 * @group certification-path
 */
class CertificationPathBuildingTest extends PHPUnit_Framework_TestCase
{
	/**
	 *
	 * @return CertificationPath
	 */
	public function testBuildPath() {
		$anchors = CertificateBundle::fromPEMBundle(
			PEMBundle::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
		$intermediate = CertificateBundle::fromPEMBundle(
			PEMBundle::fromFile(
				TEST_ASSETS_DIR . "/certs/intermediate-bundle.pem"));
		$target = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ecdsa.pem"));
		$builder = new CertificationPathBuilder($anchors);
		$path = $builder->shortestPathToTarget($target, $intermediate);
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
		$cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
		$this->assertEquals($cert, $path->certificates()[0]);
	}
	
	/**
	 * @depends testBuildPath
	 *
	 * @param CertificationPath $path
	 */
	public function testPathIntermediate(CertificationPath $path) {
		$cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-interm-ecdsa.pem"));
		$this->assertEquals($cert, $path->certificates()[1]);
	}
	
	/**
	 * @depends testBuildPath
	 *
	 * @param CertificationPath $path
	 */
	public function testPathTargete(CertificationPath $path) {
		$cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ecdsa.pem"));
		$this->assertEquals($cert, $path->certificates()[2]);
	}
	
	/**
	 * @expectedException X509\CertificationPath\Exception\PathBuildingException
	 */
	public function testBuildPathFail() {
		$anchors = CertificateBundle::fromPEMBundle(
			PEMBundle::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
		$target = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ecdsa.pem"));
		$builder = new CertificationPathBuilder($anchors);
		$builder->shortestPathToTarget($target, new CertificateBundle());
	}
}
