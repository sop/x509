<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use X501\ASN1\Name;
use X509\AttributeCertificate\AttCertIssuer;
use X509\AttributeCertificate\AttCertValidityPeriod;
use X509\AttributeCertificate\AttributeCertificate;
use X509\AttributeCertificate\AttributeCertificateInfo;
use X509\AttributeCertificate\Attributes;
use X509\AttributeCertificate\Holder;
use X509\AttributeCertificate\IssuerSerial;
use X509\AttributeCertificate\Attribute\RoleAttributeValue;
use X509\Certificate\Extensions;
use X509\Certificate\UniqueIdentifier;
use X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 */
class AttributeCertificateInfoTest extends \PHPUnit\Framework\TestCase
{
    const ISSUER_DN = "cn=Issuer";
    
    private static $_holder;
    
    private static $_issuer;
    
    private static $_validity;
    
    private static $_attribs;
    
    private static $_extensions;
    
    private static $_privKeyInfo;
    
    public static function setUpBeforeClass()
    {
        self::$_holder = new Holder(
            new IssuerSerial(
                new GeneralNames(DirectoryName::fromDNString(self::ISSUER_DN)),
                42));
        self::$_issuer = AttCertIssuer::fromName(
            Name::fromString(self::ISSUER_DN));
        self::$_validity = AttCertValidityPeriod::fromStrings(
            "2016-04-29 12:00:00", "2016-04-29 13:00:00");
        self::$_attribs = Attributes::fromAttributeValues(
            new RoleAttributeValue(new UniformResourceIdentifier("urn:admin")));
        self::$_extensions = new Extensions(
            new AuthorityKeyIdentifierExtension(true, "test"));
        self::$_privKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_holder = null;
        self::$_issuer = null;
        self::$_validity = null;
        self::$_attribs = null;
        self::$_extensions = null;
        self::$_privKeyInfo = null;
    }
    
    public function testCreate()
    {
        $aci = new AttributeCertificateInfo(self::$_holder, self::$_issuer,
            self::$_validity, self::$_attribs);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }
    
    public function testCreateWithAll()
    {
        $aci = new AttributeCertificateInfo(self::$_holder, self::$_issuer,
            self::$_validity, self::$_attribs);
        $aci = $aci->withSignature(
            new SHA256WithRSAEncryptionAlgorithmIdentifier())
            ->withSerialNumber(1)
            ->withExtensions(self::$_extensions)
            ->withIssuerUniqueID(UniqueIdentifier::fromString("uid"));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testEncode(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $tc = AttributeCertificateInfo::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $tc);
        return $tc;
    }
    
    /**
     * @depends testCreateWithAll
     * @depends testDecode
     *
     * @param AttributeCertificateInfo $ref
     * @param AttributeCertificateInfo $new
     */
    public function testRecoded(AttributeCertificateInfo $ref,
        AttributeCertificateInfo $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testVersion(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(AttributeCertificateInfo::VERSION_2, $aci->version());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testHolder(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_holder, $aci->holder());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testIssuer(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_issuer, $aci->issuer());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testSignature(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(new SHA256WithRSAEncryptionAlgorithmIdentifier(),
            $aci->signature());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testSerialNumber(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(1, $aci->serialNumber());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testValidityPeriod(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_validity, $aci->validityPeriod());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testAttributes(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_attribs, $aci->attributes());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testIssuerUniqueID(AttributeCertificateInfo $aci)
    {
        $this->assertEquals("uid", $aci->issuerUniqueID()
            ->string());
    }
    
    /**
     * @depends testCreateWithAll
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testExtensions(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_extensions, $aci->extensions());
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithHolder(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withHolder(self::$_holder);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithIssuer(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withIssuer(self::$_issuer);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithSignature(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withSignature(
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithSerial(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withSerialNumber(123);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithRandomSerial(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withRandomSerialNumber(16);
        $bin = gmp_export(gmp_init($aci->serialNumber(), 10), 1);
        $this->assertEquals(16, strlen($bin));
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithValidity(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withValidity(self::$_validity);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithAttributes(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withAttributes(self::$_attribs);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithIssuerUniqueID(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withIssuerUniqueID(UniqueIdentifier::fromString("id"));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithExtensions(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withExtensions(self::$_extensions);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testWithAdditionalExtensions(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withAdditionalExtensions(
            new AuthorityKeyIdentifierExtension(true, "test"));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }
    
    /**
     * @depends testCreateWithAll
     * @expectedException UnexpectedValueException
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testDecodeInvalidVersion(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $seq = $seq->withReplaced(0, new Integer(0));
        AttributeCertificateInfo::fromASN1($seq);
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testNoSignatureFail(AttributeCertificateInfo $aci)
    {
        $aci->signature();
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testNoSerialFail(AttributeCertificateInfo $aci)
    {
        $aci->serialNumber();
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testNoIssuerUniqueIdFail(AttributeCertificateInfo $aci)
    {
        $aci->issuerUniqueID();
    }
    
    /**
     * @depends testCreate
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testSign(AttributeCertificateInfo $aci)
    {
        $ac = $aci->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privKeyInfo);
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
    }
    
    /**
     * @depends testCreateWithAll
     * @expectedException UnexpectedValueException
     *
     * @param AttributeCertificateInfo $aci
     */
    public function testInvalidAlgoFail(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $algo = new GenericAlgorithmIdentifier("1.3.6.1.3");
        $seq = $seq->withReplaced(3, $algo->toASN1());
        AttributeCertificateInfo::fromASN1($seq);
    }
}
