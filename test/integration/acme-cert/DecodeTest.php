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
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\Extensions;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;

/**
 * Decodes reference certificate acme-rsa.pem.
 *
 * @group certificate
 * @group decode
 *
 * @internal
 */
class RefCertificateDecodeTest extends TestCase
{
    /**
     * @return Certificate
     */
    public function testCert()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        $cert = Certificate::fromPEM($pem);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends testCert
     *
     * @return TBSCertificate
     */
    public function testTBSCertificate(Certificate $cert)
    {
        $tbsCert = $cert->tbsCertificate();
        $this->assertInstanceOf(TBSCertificate::class, $tbsCert);
        return $tbsCert;
    }

    /**
     * @depends testCert
     *
     * @return AlgorithmIdentifier
     */
    public function testSignatureAlgorithm(Certificate $cert)
    {
        $algo = $cert->signatureAlgorithm();
        $this->assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends testSignatureAlgorithm
     */
    public function testSignatureAlgorithmValue(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION,
            $algo->oid());
    }

    /**
     * @depends testCert
     *
     * @return Signature
     */
    public function testSignature(Certificate $cert)
    {
        $signature = $cert->signatureValue();
        $this->assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    /**
     * @depends testSignature
     */
    public function testSignatureValue(Signature $sig)
    {
        $expected = hex2bin(
            trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.pem.sig')));
        $this->assertEquals($expected, $sig->bitString()
            ->string());
    }

    /**
     * @depends testTBSCertificate
     */
    public function testVersion(TBSCertificate $tbsCert)
    {
        $this->assertEquals(TBSCertificate::VERSION_3, $tbsCert->version());
    }

    /**
     * @depends testTBSCertificate
     */
    public function testSerial(TBSCertificate $tbsCert)
    {
        $this->assertEquals(42, $tbsCert->serialNumber());
    }

    /**
     * @depends testTBSCertificate
     */
    public function testSignatureAlgo(TBSCertificate $tbsCert)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION,
            $tbsCert->signature()
                ->oid());
    }

    /**
     * @depends testTBSCertificate
     *
     * @return Name
     */
    public function testIssuer(TBSCertificate $tbsCert)
    {
        $issuer = $tbsCert->issuer();
        $this->assertInstanceOf(Name::class, $issuer);
        return $issuer;
    }

    /**
     * @depends testIssuer
     */
    public function testIssuerDN(Name $name)
    {
        $this->assertEquals('o=ACME Ltd.,c=FI,cn=ACME Intermediate CA',
            $name->toString());
    }

    /**
     * @depends testTBSCertificate
     *
     * @return Validity
     */
    public function testValidity(TBSCertificate $tbsCert)
    {
        $validity = $tbsCert->validity();
        $this->assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    /**
     * @depends testValidity
     */
    public function testNotBefore(Validity $validity)
    {
        $str = $validity->notBefore()
            ->dateTime()
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('M j H:i:s Y T');
        $this->assertEquals('Jan 1 12:00:00 2016 GMT', $str);
    }

    /**
     * @depends testValidity
     */
    public function testNotAfter(Validity $validity)
    {
        $str = $validity->notAfter()
            ->dateTime()
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('M j H:i:s Y T');
        $this->assertEquals('Jan 2 15:04:05 2026 GMT', $str);
    }

    /**
     * @depends testTBSCertificate
     *
     * @return Name
     */
    public function testSubject(TBSCertificate $tbsCert)
    {
        $subject = $tbsCert->subject();
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
     * @depends testTBSCertificate
     *
     * @return PublicKeyInfo
     */
    public function testSubjectPublicKeyInfo(TBSCertificate $tbsCert)
    {
        $pki = $tbsCert->subjectPublicKeyInfo();
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testSubjectPublicKeyInfo
     */
    public function testPublicKeyAlgo(PublicKeyInfo $pki)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION,
            $pki->algorithmIdentifier()
                ->oid());
    }

    /**
     * @depends testSubjectPublicKeyInfo
     */
    public function testPublicKey(PublicKeyInfo $pki)
    {
        $pk = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        $this->assertEquals($pk, $pki->publicKey());
    }

    /**
     * @depends testTBSCertificate
     *
     * @return Extensions
     */
    public function testExtensions(TBSCertificate $tbsCert)
    {
        $extensions = $tbsCert->extensions();
        $this->assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }
}
