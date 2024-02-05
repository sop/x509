<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\X509\Certificate\Extension\CertificatePoliciesExtension;
use Sop\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use Sop\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class CertificatePoliciesTest extends TestCase
{
    public const INFO_OID = '1.3.6.1.3';

    public const CPS_URI = 'urn:test';

    public const NOTICE_TXT = 'Notice';

    public const REF_ORG = 'ACME Ltd.';

    public function testCreateCPS()
    {
        $qual = new CPSQualifier('urn:test');
        $this->assertInstanceOf(PolicyQualifierInfo::class, $qual);
        return $qual;
    }

    public function testCreateNotice()
    {
        $qual = new UserNoticeQualifier(DisplayText::fromString('Notice'),
            new NoticeReference(DisplayText::fromString(self::REF_ORG), 1, 2, 3));
        $this->assertInstanceOf(PolicyQualifierInfo::class, $qual);
        return $qual;
    }

    /**
     * @depends testCreateCPS
     * @depends testCreateNotice
     */
    public function testCreatePolicyInfo(PolicyQualifierInfo $q1,
        PolicyQualifierInfo $q2)
    {
        $info = new PolicyInformation(self::INFO_OID, $q1, $q2);
        $this->assertInstanceOf(PolicyInformation::class, $info);
        return $info;
    }

    /**
     * @depends testCreatePolicyInfo
     */
    public function testCreate(PolicyInformation $info)
    {
        $ext = new CertificatePoliciesExtension(true, $info,
            new PolicyInformation('1.3.6.1.3.10'));
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_CERTIFICATE_POLICIES, $ext->oid());
    }

    /**
     * @depends testCreate
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Extension $ext)
    {
        $seq = $ext->toASN1();
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
        $ext = CertificatePoliciesExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testCount(CertificatePoliciesExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(CertificatePoliciesExtension $ext)
    {
        $values = [];
        foreach ($ext as $info) {
            $values[] = $info;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(PolicyInformation::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testGetFail(CertificatePoliciesExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->get('1.2.3');
    }

    public function testHasAnyPolicy()
    {
        $ext = new CertificatePoliciesExtension(true,
            new PolicyInformation(PolicyInformation::OID_ANY_POLICY));
        $this->assertTrue($ext->hasAnyPolicy());
    }

    public function testAnyPolicyFail()
    {
        $ext = new CertificatePoliciesExtension(true,
            new PolicyInformation('1.3.6.1.3'));
        $this->expectException(LogicException::class);
        $ext->anyPolicy();
    }

    /**
     * @depends testCreate
     */
    public function testInfo(CertificatePoliciesExtension $ext)
    {
        $info = $ext->get(self::INFO_OID);
        $this->assertInstanceOf(PolicyInformation::class, $info);
        return $info;
    }

    /**
     * @depends testInfo
     */
    public function testInfoCount(PolicyInformation $info)
    {
        $this->assertCount(2, $info);
    }

    /**
     * @depends testInfo
     */
    public function testInfoIterator(PolicyInformation $info)
    {
        $values = [];
        foreach ($info as $qual) {
            $values[] = $qual;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }

    /**
     * @depends testInfo
     */
    public function testCPS(PolicyInformation $info)
    {
        $qual = $info->CPSQualifier();
        $this->assertInstanceOf(CPSQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends testCPS
     */
    public function testCPSURI(CPSQualifier $cps)
    {
        $this->assertEquals(self::CPS_URI, $cps->uri());
    }

    /**
     * @depends testInfo
     */
    public function testUserNotice(PolicyInformation $info)
    {
        $qual = $info->userNoticeQualifier();
        $this->assertInstanceOf(UserNoticeQualifier::class, $qual);
        return $qual;
    }

    /**
     * @depends testUserNotice
     */
    public function testUserNoticeExplicit(UserNoticeQualifier $notice)
    {
        $this->assertEquals(self::NOTICE_TXT, $notice->explicitText());
    }

    /**
     * @depends testUserNotice
     */
    public function testUserNoticeRef(UserNoticeQualifier $notice)
    {
        $ref = $notice->noticeRef();
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends testUserNoticeRef
     */
    public function testRefOrg(NoticeReference $ref)
    {
        $this->assertEquals(self::REF_ORG, $ref->organization());
    }

    /**
     * @depends testUserNoticeRef
     */
    public function testRefNumbers(NoticeReference $ref)
    {
        $this->assertEquals([1, 2, 3], $ref->numbers());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(CertificatePoliciesExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasCertificatePolicies());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->certificatePolicies();
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
    }

    public function testEncodeEmptyFail()
    {
        $ext = new CertificatePoliciesExtension(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    public function testDecodeEmptyFail()
    {
        $seq = new Sequence();
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_CERTIFICATE_POLICIES),
            new OctetString($seq->toDER()));
        $this->expectException(UnexpectedValueException::class);
        CertificatePoliciesExtension::fromASN1($ext_seq);
    }
}
