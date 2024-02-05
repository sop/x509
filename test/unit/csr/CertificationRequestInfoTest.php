<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use Sop\X509\CertificationRequest\Attributes;
use Sop\X509\CertificationRequest\CertificationRequest;
use Sop\X509\CertificationRequest\CertificationRequestInfo;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group csr
 *
 * @internal
 */
class CertificationRequestInfoTest extends TestCase
{
    public const SAN_DN = 'cn=Alt Name';

    private static $_subject;

    private static $_privateKeyInfo;

    private static $_attribs;

    public static function setUpBeforeClass(): void
    {
        self::$_subject = Name::fromString('cn=Subject');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $extensions = new Extensions(
            new SubjectAlternativeNameExtension(true,
                new GeneralNames(DirectoryName::fromDNString(self::SAN_DN))));
        self::$_attribs = Attributes::fromAttributeValues(
            new ExtensionRequestValue($extensions));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_subject = null;
        self::$_privateKeyInfo = null;
        self::$_attribs = null;
    }

    public function testCreate()
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        $cri = new CertificationRequestInfo(self::$_subject, $pkinfo);
        $cri = $cri->withAttributes(self::$_attribs);
        $this->assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(CertificationRequestInfo $cri)
    {
        $seq = $cri->toASN1();
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
        $cert = CertificationRequestInfo::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(CertificationRequestInfo::class, $cert);
        return $cert;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(CertificationRequestInfo $ref,
        CertificationRequestInfo $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testVersion(CertificationRequestInfo $cri)
    {
        $this->assertEquals(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    /**
     * @depends testCreate
     */
    public function testSubject(CertificationRequestInfo $cri)
    {
        $this->assertEquals(self::$_subject, $cri->subject());
    }

    /**
     * @depends testCreate
     */
    public function testWithSubject(CertificationRequestInfo $cri)
    {
        static $name = 'cn=New Name';
        $cri = $cri->withSubject(Name::fromString($name));
        $this->assertEquals($name, $cri->subject());
    }

    /**
     * @depends testCreate
     */
    public function testWithExtensionRequest(CertificationRequestInfo $cri)
    {
        $cri = $cri->withExtensionRequest(new Extensions());
        $this->assertTrue(
            $cri->attributes()
                ->hasExtensionRequest());
    }

    public function testWithExtensionRequestWithoutAttributes()
    {
        $cri = new CertificationRequestInfo(self::$_subject,
            self::$_privateKeyInfo->publicKeyInfo());
        $cri = $cri->withExtensionRequest(new Extensions());
        $this->assertTrue(
            $cri->attributes()
                ->hasExtensionRequest());
    }

    /**
     * @depends testCreate
     */
    public function testSubjectPKI(CertificationRequestInfo $cri)
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        $this->assertEquals($pkinfo, $cri->subjectPKInfo());
    }

    /**
     * @depends testCreate
     */
    public function testAttribs(CertificationRequestInfo $cri)
    {
        $attribs = $cri->attributes();
        $this->assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    public function testNoAttributesFail()
    {
        $cri = new CertificationRequestInfo(self::$_subject,
            self::$_privateKeyInfo->publicKeyInfo());
        $this->expectException(LogicException::class);
        $cri->attributes();
    }

    /**
     * @depends testAttribs
     */
    public function testSAN(Attributes $attribs)
    {
        $dn = $attribs->extensionRequest()
            ->extensions()
            ->subjectAlternativeName()
            ->names()
            ->firstDN()
            ->toString();
        $this->assertEquals(self::SAN_DN, $dn);
    }

    public function testInvalidVersionFail()
    {
        $seq = new Sequence(new Integer(1), self::$_subject->toASN1(),
            self::$_privateKeyInfo->publicKeyInfo()->toASN1());
        $this->expectException(UnexpectedValueException::class);
        CertificationRequestInfo::fromASN1($seq);
    }

    /**
     * @depends testCreate
     */
    public function testSign(CertificationRequestInfo $cri)
    {
        $csr = $cri->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privateKeyInfo);
        $this->assertInstanceOf(CertificationRequest::class, $csr);
    }
}
