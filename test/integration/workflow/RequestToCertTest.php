<?php

use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X501\ASN1\Name;
use X509\Certificate\Certificate;
use X509\Certificate\TBSCertificate;
use X509\Certificate\Validity;
use X509\CertificationRequest\CertificationRequest;
use X509\CertificationRequest\CertificationRequestInfo;


/**
 * @group workflow
 */
class RequestToCertTest extends PHPUnit_Framework_TestCase
{
	/**
	 *
	 * @return PEM
	 */
	public function testCreateRequest() {
		$private_key_info = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		$public_key_info = PublicKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem"));
		$cri = new CertificationRequestInfo(Name::fromString("cn=Test"), 
			$public_key_info);
		$pem = $cri->sign(Crypto::getDefault(), 
			new SHA1WithRSAEncryptionAlgorithmIdentifier(), $private_key_info);
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testCreateRequest
	 *
	 * @param PEM $csr
	 * @return PEM
	 */
	public function testIssueCertificate(PEM $csr) {
		$cr = CertificationRequest::fromPEM($csr);
		$this->assertTrue($cr->verify(Crypto::getDefault()));
		$privkey_info = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key.pem"));
		$tbs_cert = TBSCertificate::fromCSR($cr);
		$tbs_cert = $tbs_cert->withIssuer(Name::fromString("cn=Issuer"));
		$tbs_cert = $tbs_cert->withValidity(
			Validity::fromStrings("now - 1 hour", "now + 1 hour"));
		$pem = $tbs_cert->sign(Crypto::getDefault(), 
			new ECDSAWithSHA1AlgorithmIdentifier(), $privkey_info);
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testIssueCertificate
	 *
	 * @param PEM $crt
	 * @return Certificate
	 */
	public function testCertificate(PEM $crt) {
		$cert = Certificate::fromPEM($crt);
		$this->assertInstanceOf(Certificate::class, $cert);
		return $cert;
	}
	
	/**
	 * @depends testCertificate
	 *
	 * @param Certificate $cert
	 */
	public function testSignature(Certificate $cert) {
		$pubkey_info = PublicKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key.pem"));
		$this->assertTrue($cert->verify(Crypto::getDefault(), $pubkey_info));
	}
}
