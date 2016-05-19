<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use CryptoUtil\PEM\PEMBundle;
use X501\ASN1\Name;
use X509\Certificate\Certificate;
use X509\Certificate\CertificateBundle;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;


/**
 * @group certificate
 */
class CertificateBundleTest extends PHPUnit_Framework_TestCase
{
	private static $_pem1;
	
	private static $_cert1;
	
	private static $_pem2;
	
	private static $_cert2;
	
	private static $_pem3;
	
	public static function setUpBeforeClass() {
		self::$_pem1 = PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-ca.pem");
		self::$_cert1 = Certificate::fromPEM(self::$_pem1);
		self::$_pem2 = PEM::fromFile(
			TEST_ASSETS_DIR . "/certs/acme-interm-rsa.pem");
		self::$_cert2 = Certificate::fromPEM(self::$_pem2);
		self::$_pem3 = PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem");
	}
	
	public static function tearDownAfterClass() {
		self::$_pem1 = null;
		self::$_cert1 = null;
		self::$_pem2 = null;
		self::$_cert2 = null;
		self::$_pem3 = null;
	}
	
	public function testCreate() {
		$bundle = new CertificateBundle(self::$_cert1, self::$_cert2);
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
		$id = self::$_cert2->tbsCertificate()
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
		$bundle = $bundle->withPEM(self::$_pem3);
		$this->assertCount(3, $bundle);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificateBundle $bundle
	 */
	public function testWithPEMBundle(CertificateBundle $bundle) {
		$bundle = $bundle->withPEMBundle(new PEMBundle(self::$_pem3));
		$this->assertCount(3, $bundle);
	}
	
	public function testFromPEMBundle() {
		$bundle = CertificateBundle::fromPEMBundle(
			new PEMBundle(self::$_pem1, self::$_pem2));
		$this->assertInstanceOf(CertificateBundle::class, $bundle);
	}
	
	public function testFromPEMs() {
		$bundle = CertificateBundle::fromPEMs(self::$_pem1, self::$_pem2);
		$this->assertInstanceOf(CertificateBundle::class, $bundle);
	}
	
	public function testSearchBySubjectKeyHavingNoID() {
		$priv_key_info = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		$tc = new TBSCertificate(Name::fromString("cn=Subject"), 
			$priv_key_info->publicKeyInfo(), Name::fromString("cn=Issuer"), 
			Validity::fromStrings(null, null));
		$cert = $tc->sign(Crypto::getDefault(), 
			new SHA1WithRSAEncryptionAlgorithmIdentifier(), $priv_key_info);
		$bundle = new CertificateBundle($cert);
		$this->assertEmpty($bundle->allBySubjectKeyIdentifier("nope"));
	}
}
