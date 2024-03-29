<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use Sop\X509\CertificationRequest\Attributes;
use Sop\X509\CertificationRequest\CertificationRequest;
use Sop\X509\CertificationRequest\CertificationRequestInfo;

/**
 * @group csr
 * @group decode
 *
 * @internal
 */
class RefCSRDecodeTest extends TestCase
{
    /**
     * @return CertificationRequest
     */
    public function testCSR()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.csr');
        $csr = CertificationRequest::fromPEM($pem);
        $this->assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }

    /**
     * @depends testCSR
     *
     * @return CertificationRequestInfo
     */
    public function testCertificationRequestInfo(CertificationRequest $cr)
    {
        $cri = $cr->certificationRequestInfo();
        $this->assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    /**
     * @depends testCSR
     *
     * @return AlgorithmIdentifier
     */
    public function testSignatureAlgorithm(CertificationRequest $cr)
    {
        $algo = $cr->signatureAlgorithm();
        $this->assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends testSignatureAlgorithm
     */
    public function testAlgoType(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION,
            $algo->oid());
    }

    /**
     * @depends testCSR
     *
     * @return Signature
     */
    public function testSignature(CertificationRequest $cr)
    {
        $signature = $cr->signature();
        $this->assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    /**
     * @depends testSignature
     */
    public function testSignatureValue(Signature $signature)
    {
        $expected = hex2bin(
            trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.csr.sig')));
        $this->assertEquals($expected,
            $signature->bitString()
                ->string());
    }

    /**
     * @depends testCertificationRequestInfo
     */
    public function testVersion(CertificationRequestInfo $cri)
    {
        $this->assertEquals(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    /**
     * @depends testCertificationRequestInfo
     *
     * @return Name
     */
    public function testSubject(CertificationRequestInfo $cri)
    {
        $subject = $cri->subject();
        $this->assertInstanceOf(Name::class, $subject);
        return $subject;
    }

    /**
     * @depends testSubject
     */
    public function testSubjectDN(Name $name)
    {
        $this->assertEquals('o=ACME Ltd.,c=FI,cn=example.com', $name->toString());
    }

    /**
     * @depends testCertificationRequestInfo
     *
     * @return PublicKeyInfo
     */
    public function testSubjectPKInfo(CertificationRequestInfo $cri)
    {
        $info = $cri->subjectPKInfo();
        $this->assertInstanceOf(PublicKeyInfo::class, $info);
        return $info;
    }

    /**
     * @depends testSubjectPKInfo
     */
    public function testPublicKeyAlgo(PublicKeyInfo $info)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION,
            $info->algorithmIdentifier()
                ->oid());
    }

    /**
     * @depends testSubjectPKInfo
     */
    public function testPublicKey(PublicKeyInfo $info)
    {
        $pk = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        $this->assertEquals($pk, $info->publicKey());
    }

    /**
     * @depends testCertificationRequestInfo
     *
     * @return Attributes
     */
    public function testAttributes(CertificationRequestInfo $cri)
    {
        $this->assertTrue($cri->hasAttributes());
        $attribs = $cri->attributes();
        $this->assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends testAttributes
     *
     * @return ExtensionRequestValue
     */
    public function testExtensionRequestAttribute(Attributes $attribs)
    {
        $attr = ExtensionRequestValue::fromSelf(
            $attribs->firstOf(ExtensionRequestValue::OID)->first());
        $this->assertInstanceOf(ExtensionRequestValue::class, $attr);
        return $attr;
    }

    /**
     * @depends testExtensionRequestAttribute
     *
     * @return Extensions
     */
    public function testRequestedExtensions(ExtensionRequestValue $attr)
    {
        $extensions = $attr->extensions();
        $this->assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }

    /**
     * @depends testRequestedExtensions
     *
     * @return KeyUsageExtension
     */
    public function testKeyUsageExtension(Extensions $extensions)
    {
        $ext = $extensions->get(Extension::OID_KEY_USAGE);
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testKeyUsageExtension
     */
    public function testKeyUsageExtensionValue(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isKeyEncipherment());
        $this->assertTrue($ext->isKeyCertSign());
    }
}
