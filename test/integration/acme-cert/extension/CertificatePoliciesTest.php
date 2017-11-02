<?php

declare(strict_types=1);

use X509\Certificate\Extension\CertificatePoliciesExtension;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

require_once __DIR__ . "/RefExtTestHelper.php";

/**
 * @group certificate
 * @group extension
 * @group decode
 */
class RefCertificatePoliciesTest extends RefExtTestHelper
{
    /**
     *
     * @param Extensions $extensions
     * @return CertificatePoliciesExtension
     */
    public function testCertificatePoliciesExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_CERTIFICATE_POLICIES);
        $this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testCertificatePoliciesExtension
     *
     * @param CertificatePoliciesExtension $cpe
     * @return PolicyInformation
     */
    public function testPolicyInformation(CertificatePoliciesExtension $cpe)
    {
        $pi = $cpe->get("1.3.6.1.4.1.45710.2.2.1");
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }
    
    /**
     * @depends testPolicyInformation
     *
     * @param PolicyInformation $pi
     * @return CPSQualifier
     */
    public function testPolicyCPSQualifier(PolicyInformation $pi)
    {
        $cps = $pi->get(PolicyQualifierInfo::OID_CPS);
        $this->assertInstanceOf(CPSQualifier::class, $cps);
        return $cps;
    }
    
    /**
     * @depends testPolicyCPSQualifier
     *
     * @param CPSQualifier $cps
     */
    public function testPolicyCPSQualifierURI(CPSQualifier $cps)
    {
        $this->assertEquals("http://example.com/cps.html", $cps->uri());
    }
    
    /**
     * @depends testPolicyInformation
     *
     * @param PolicyInformation $pi
     * @return UserNoticeQualifier
     */
    public function testPolicyUserNoticeQualifier(PolicyInformation $pi)
    {
        $un = $pi->get(PolicyQualifierInfo::OID_UNOTICE);
        $this->assertInstanceOf(UserNoticeQualifier::class, $un);
        return $un;
    }
    
    /**
     * @depends testPolicyUserNoticeQualifier
     *
     * @param UserNoticeQualifier $un
     */
    public function testPolicyUserNoticeQualifierText(UserNoticeQualifier $un)
    {
        $this->assertEquals("All your base are belong to us!",
            $un->explicitText()
                ->string());
    }
    
    /**
     * @depends testPolicyUserNoticeQualifier
     *
     * @param UserNoticeQualifier $un
     * @return NoticeReference
     */
    public function testPolicyUserNoticeQualifierRef(UserNoticeQualifier $un)
    {
        $ref = $un->noticeRef();
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }
    
    /**
     * @depends testPolicyUserNoticeQualifierRef
     *
     * @param NoticeReference $ref
     */
    public function testPolicyUserNoticeQualifierOrganization(
        NoticeReference $ref)
    {
        $this->assertEquals("Toaplan Co., Ltd.",
            $ref->organization()
                ->string());
    }
    
    /**
     * @depends testPolicyUserNoticeQualifierRef
     *
     * @param NoticeReference $ref
     */
    public function testPolicyUserNoticeQualifierNumbers(NoticeReference $ref)
    {
        $this->assertEquals([1, 2], $ref->numbers());
    }
}
