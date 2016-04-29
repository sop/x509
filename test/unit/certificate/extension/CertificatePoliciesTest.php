<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\CertificatePoliciesExtension;
use X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use X509\Certificate\Extension\CertificatePolicy\DisplayText;
use X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extensions;


/**
 * @group certificate
 * @group extension
 */
class CertificatePoliciesTest extends PHPUnit_Framework_TestCase
{
	const INFO_OID = "1.3.6.1.3";
	const CPS_URI = "urn:test";
	const NOTICE_TXT = "Notice";
	const REF_ORG = "ACME Ltd.";
	
	public function testCreateCPS() {
		$qual = new CPSQualifier("urn:test");
		$this->assertInstanceOf(PolicyQualifierInfo::class, $qual);
		return $qual;
	}
	
	public function testCreateNotice() {
		$qual = new UserNoticeQualifier(DisplayText::fromString("Notice"), 
			new NoticeReference(DisplayText::fromString(self::REF_ORG), 1, 2, 3));
		$this->assertInstanceOf(PolicyQualifierInfo::class, $qual);
		return $qual;
	}
	
	/**
	 * @depends testCreateCPS
	 * @depends testCreateNotice
	 *
	 * @param PolicyQualifierInfo $q1
	 * @param PolicyQualifierInfo $q2
	 */
	public function testCreatePolicyInfo(PolicyQualifierInfo $q1, 
			PolicyQualifierInfo $q2) {
		$info = new PolicyInformation(self::INFO_OID, $q1, $q2);
		$this->assertInstanceOf(PolicyInformation::class, $info);
		return $info;
	}
	
	/**
	 * @depends testCreatePolicyInfo
	 *
	 * @param PolicyInformation $info
	 */
	public function testCreate(PolicyInformation $info) {
		$ext = new CertificatePoliciesExtension(true, $info);
		$this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testOID(Extension $ext) {
		$this->assertEquals(Extension::OID_CERTIFICATE_POLICIES, $ext->oid());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testCritical(Extension $ext) {
		$this->assertTrue($ext->isCritical());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testEncode(Extension $ext) {
		$seq = $ext->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$ext = CertificatePoliciesExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Extension $ref
	 * @param Extension $new
	 */
	public function testRecoded(Extension $ref, Extension $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificatePoliciesExtension $ext
	 */
	public function testCount(CertificatePoliciesExtension $ext) {
		$this->assertCount(1, $ext);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificatePoliciesExtension $ext
	 */
	public function testIterator(CertificatePoliciesExtension $ext) {
		$values = array();
		foreach ($ext as $info) {
			$values[] = $info;
		}
		$this->assertCount(1, $values);
		$this->assertContainsOnlyInstancesOf(PolicyInformation::class, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificatePoliciesExtension $ext
	 */
	public function testInfo(CertificatePoliciesExtension $ext) {
		$info = $ext->get(self::INFO_OID);
		$this->assertInstanceOf(PolicyInformation::class, $info);
		return $info;
	}
	
	/**
	 * @depends testInfo
	 *
	 * @param PolicyInformation $info
	 */
	public function testInfoCount(PolicyInformation $info) {
		$this->assertCount(2, $info);
	}
	
	/**
	 * @depends testInfo
	 *
	 * @param PolicyInformation $info
	 */
	public function testInfoIterator(PolicyInformation $info) {
		$values = array();
		foreach ($info as $qual) {
			$values[] = $qual;
		}
		$this->assertCount(2, $values);
		$this->assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, 
			$values);
	}
	
	/**
	 * @depends testInfo
	 *
	 * @param PolicyInformation $info
	 */
	public function testCPS(PolicyInformation $info) {
		$qual = $info->CPSQualifier();
		$this->assertInstanceOf(CPSQualifier::class, $qual);
		return $qual;
	}
	
	/**
	 * @depends testCPS
	 *
	 * @param CPSQualifier $cps
	 */
	public function testCPSURI(CPSQualifier $cps) {
		$this->assertEquals(self::CPS_URI, $cps->uri());
	}
	
	/**
	 * @depends testInfo
	 *
	 * @param PolicyInformation $info
	 */
	public function testUserNotice(PolicyInformation $info) {
		$qual = $info->userNoticeQualifier();
		$this->assertInstanceOf(UserNoticeQualifier::class, $qual);
		return $qual;
	}
	
	/**
	 * @depends testUserNotice
	 *
	 * @param UserNoticeQualifier $notice
	 */
	public function testUserNoticeExplicit(UserNoticeQualifier $notice) {
		$this->assertEquals(self::NOTICE_TXT, $notice->explicitText());
	}
	
	/**
	 * @depends testUserNotice
	 *
	 * @param UserNoticeQualifier $notice
	 */
	public function testUserNoticeRef(UserNoticeQualifier $notice) {
		$ref = $notice->noticeRef();
		$this->assertInstanceOf(NoticeReference::class, $ref);
		return $ref;
	}
	
	/**
	 * @depends testUserNoticeRef
	 *
	 * @param NoticeReference $ref
	 */
	public function testRefOrg(NoticeReference $ref) {
		$this->assertEquals(self::REF_ORG, $ref->organization());
	}
	
	/**
	 * @depends testUserNoticeRef
	 *
	 * @param NoticeReference $ref
	 */
	public function testRefNumbers(NoticeReference $ref) {
		$this->assertEquals([1, 2, 3], $ref->numbers());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CertificatePoliciesExtension $ext
	 */
	public function testExtensions(CertificatePoliciesExtension $ext) {
		$extensions = new Extensions($ext);
		$this->assertTrue($extensions->hasCertificatePolicies());
		return $extensions;
	}
	
	/**
	 * @depends testExtensions
	 *
	 * @param Extensions $exts
	 */
	public function testFromExtensions(Extensions $exts) {
		$ext = $exts->certificatePolicies();
		$this->assertInstanceOf(CertificatePoliciesExtension::class, $ext);
	}
}
