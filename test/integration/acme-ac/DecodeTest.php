<?php

use ASN1\Type\Constructed\Sequence;
use CryptoUtil\ASN1\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use CryptoUtil\Crypto\Crypto;
use CryptoUtil\PEM\PEM;
use X509\AttributeCertificate\AttributeCertificate;
use X509\AttributeCertificate\AttributeCertificateInfo;
use X509\Certificate\Certificate;


/**
 * Decodes reference attribute certificate acme-ac.pem.
 *
 * @group ac
 * @group decode
 */
class RefACDecodeTest extends PHPUnit_Framework_TestCase
{
	/**
	 *
	 * @return PEM
	 */
	public function testPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ac/acme-ac.pem");
		$this->assertEquals(PEM::TYPE_ATTRIBUTE_CERTIFICATE, $pem->type());
		return $pem;
	}
	
	/**
	 * @depends testPEM
	 *
	 * @param PEM $pem
	 * @return AttributeCertificate
	 */
	public function testAC(PEM $pem) {
		$seq = Sequence::fromDER($pem->data());
		$ac = AttributeCertificate::fromASN1($seq);
		$this->assertInstanceOf(AttributeCertificate::class, $ac);
		return $ac;
	}
	
	/**
	 * @depends testAC
	 *
	 * @param AttributeCertificate $ac
	 * @return AttributeCertificateInfo
	 */
	public function testACI(AttributeCertificate $ac) {
		$aci = $ac->acinfo();
		$this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
		return $aci;
	}
	
	/**
	 * @depends testAC
	 *
	 * @param AttributeCertificate $ac
	 * @return AlgorithmIdentifier
	 */
	public function testSignatureAlgo(AttributeCertificate $ac) {
		$algo = $ac->signatureAlgorithm();
		$this->assertInstanceOf(
			SHA256WithRSAEncryptionAlgorithmIdentifier::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testAC
	 *
	 * @param AttributeCertificate $ac
	 */
	public function testVerifySignature(AttributeCertificate $ac) {
		$cert = Certificate::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.pem"));
		$pubkey_info = $cert->tbsCertificate()->subjectPublicKeyInfo();
		$this->assertTrue($ac->verify(Crypto::getDefault(), $pubkey_info));
	}
}
