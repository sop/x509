<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\AttributeCertificate\ObjectDigestInfo;
use Sop\X509\AttributeCertificate\V2Form;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group ac
 *
 * @internal
 */
class V2FormTest extends TestCase
{
    private static $_issuerName;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerName = new GeneralNames(
            DirectoryName::fromDNString('cn=Test'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuerName = null;
    }

    public function testCreate()
    {
        $issuer = new V2Form(self::$_issuerName);
        $this->assertInstanceOf(AttCertIssuer::class, $issuer);
        return $issuer;
    }

    /**
     * @depends testCreate
     *
     * @param V2Form $issuer
     */
    public function testEncode(V2Form $issuer)
    {
        $el = $issuer->toASN1();
        $this->assertInstanceOf(ImplicitlyTaggedType::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $issuer = V2Form::fromASN1(Element::fromDER($data)->asUnspecified());
        $this->assertInstanceOf(V2Form::class, $issuer);
        return $issuer;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param V2Form $ref
     * @param V2Form $new
     */
    public function testRecoded(V2Form $ref, V2Form $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param V2Form $issuer
     */
    public function testIssuerName(V2Form $issuer)
    {
        $this->assertEquals(self::$_issuerName, $issuer->issuerName());
    }

    public function testNoIssuerNameFail()
    {
        $issuer = new V2Form();
        $this->expectException(\LogicException::class);
        $issuer->issuerName();
    }

    /**
     * @depends testCreate
     *
     * @param V2Form $issuer
     */
    public function testName(V2Form $issuer)
    {
        $this->assertEquals('cn=Test', $issuer->name());
    }

    public function testDecodeWithAll()
    {
        $iss_ser = new IssuerSerial(self::$_issuerName, 1);
        $odi = new ObjectDigestInfo(ObjectDigestInfo::TYPE_PUBLIC_KEY,
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), new BitString(''));
        $el = new ImplicitlyTaggedType(0,
            new Sequence(self::$_issuerName->toASN1(),
                new ImplicitlyTaggedType(0, $iss_ser->toASN1()),
                new ImplicitlyTaggedType(1, $odi->toASN1())));
        $issuer = V2Form::fromASN1($el->asUnspecified());
        $this->assertInstanceOf(V2Form::class, $issuer);
        return $issuer;
    }

    /**
     * @depends testDecodeWithAll
     *
     * @param V2Form $issuer
     */
    public function testEncodeWithAll(V2Form $issuer)
    {
        $el = $issuer->toASN1();
        $this->assertInstanceOf(ImplicitlyTaggedType::class, $el);
    }
}
