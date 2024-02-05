<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\X509\AttributeCertificate\AttributeCertificate;
use Sop\X509\AttributeCertificate\AttributeCertificateInfo;
use Sop\X509\Certificate\Certificate;

/**
 * Decodes reference attribute certificate acme-ac.pem.
 *
 * @group ac
 * @group decode
 *
 * @internal
 */
class RefACDecodeTest extends TestCase
{
    /**
     * @return PEM
     */
    public function testPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem');
        $this->assertEquals(PEM::TYPE_ATTRIBUTE_CERTIFICATE, $pem->type());
        return $pem;
    }

    /**
     * @depends testPEM
     *
     * @return AttributeCertificate
     */
    public function testAC(PEM $pem)
    {
        $seq = Sequence::fromDER($pem->data());
        $ac = AttributeCertificate::fromASN1($seq);
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    /**
     * @depends testAC
     *
     * @return AttributeCertificateInfo
     */
    public function testACI(AttributeCertificate $ac)
    {
        $aci = $ac->acinfo();
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @depends testAC
     *
     * @return AlgorithmIdentifier
     */
    public function testSignatureAlgo(AttributeCertificate $ac)
    {
        $algo = $ac->signatureAlgorithm();
        $this->assertInstanceOf(
            SHA256WithRSAEncryptionAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends testAC
     */
    public function testVerifySignature(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $pubkey_info = $cert->tbsCertificate()->subjectPublicKeyInfo();
        $this->assertTrue($ac->verify($pubkey_info));
    }
}
