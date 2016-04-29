<?php

use CryptoUtil\PEM\PEM;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;


/**
 * @group certificate
 */
class CertificateBundleTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$cert1 = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
		$cert2 = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-interm-rsa.pem"));
		$bundle = new CertificateBundle($cert1, $cert2);
		$this->assertInstanceOf(CertificateBundle::class, $bundle);
		return $bundle;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificateBundle $bundle
	 */
	public function testCount(CertificateBundle $bundle) {
		$this->assertCount(2, $bundle);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificateBundle $bundle
	 */
	public function testAll(CertificateBundle $bundle) {
		$this->assertCount(2, $bundle->all());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificateBundle $bundle
	 */
	public function testIterator(CertificateBundle $bundle) {
		$values = array();
		foreach ($bundle as $cert) {
			$values[] = $cert;
		}
		$this->assertCount(2, $values);
		$this->assertContainsOnlyInstancesOf(Certificate::class, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificateBundle $bundle
	 */
	public function testAllBySubjectKeyID(CertificateBundle $bundle) {
		$cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem"));
		$id = $cert->tbsCertificate()
			->extensions()
			->subjectKeyIdentifier()
			->keyIdentifier();
		$certs = $bundle->allBySubjectKeyIdentifier($id);
		$this->assertCount(1, $certs);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificateBundle $bundle
	 */
	public function testWithPEM(CertificateBundle $bundle) {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem");
		$bundle = $bundle->withPEM($pem);
		$this->assertCount(3, $bundle);
	}
}
