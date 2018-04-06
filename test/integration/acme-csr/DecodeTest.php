<?php

declare(strict_types=1);

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use X501\ASN1\Name;
use X509\Certificate\Extensions;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\KeyUsageExtension;
use X509\CertificationRequest\Attributes;
use X509\CertificationRequest\CertificationRequest;
use X509\CertificationRequest\CertificationRequestInfo;
use X509\CertificationRequest\Attribute\ExtensionRequestValue;

/**
 * @group csr
 * @group decode
 */
class RefCSRDecodeTest extends \PHPUnit\Framework\TestCase
{
    /**
     *
     * @return CertificationRequest
     */
    public function testCSR()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/certs/acme-rsa.csr");
        $csr = CertificationRequest::fromPEM($pem);
        $this->assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }
    
    /**
     * @depends testCSR
     *
     * @param CertificationRequest $cr
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
     * @param CertificationRequest $cr
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
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testAlgoType(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION,
            $algo->oid());
    }
    
    /**
     * @depends testCSR
     *
     * @param CertificationRequest $cr
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
     *
     * @param Signature $signature
     */
    public function testSignatureValue(Signature $signature)
    {
        $expected = hex2bin(
            trim(file_get_contents(TEST_ASSETS_DIR . "/certs/acme-rsa.csr.sig")));
        $this->assertEquals($expected,
            $signature->bitString()
                ->string());
    }
    
    /**
     * @depends testCertificationRequestInfo
     *
     * @param CertificationRequestInfo $cri
     */
    public function testVersion(CertificationRequestInfo $cri)
    {
        $this->assertEquals(CertificationRequestInfo::VERSION_1, $cri->version());
    }
    
    /**
     * @depends testCertificationRequestInfo
     *
     * @param CertificationRequestInfo $cri
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
     *
     * @param Name $name
     */
    public function testSubjectDN(Name $name)
    {
        $this->assertEquals("o=ACME Ltd.,c=FI,cn=example.com", $name->toString());
    }
    
    /**
     * @depends testCertificationRequestInfo
     *
     * @param CertificationRequestInfo $cri
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
     *
     * @param PublicKeyInfo $info
     */
    public function testPublicKeyAlgo(PublicKeyInfo $info)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION,
            $info->algorithmIdentifier()
                ->oid());
    }
    
    /**
     * @depends testSubjectPKInfo
     *
     * @param PublicKeyInfo $info
     */
    public function testPublicKey(PublicKeyInfo $info)
    {
        $pk = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/certs/keys/acme-rsa.pem"))->publicKey();
        $this->assertEquals($pk, $info->publicKey());
    }
    
    /**
     * @depends testCertificationRequestInfo
     *
     * @param CertificationRequestInfo $cri
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
     * @param Attributes $attribs
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
     * @param ExtensionRequestValue $attr
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
     * @param Extensions $extensions
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
     *
     * @param KeyUsageExtension $ext
     */
    public function testKeyUsageExtensionValue(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isKeyEncipherment());
        $this->assertTrue($ext->isKeyCertSign());
    }
}
