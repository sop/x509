<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use X509\Certificate\Extension\CertificatePolicy\DisplayText;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 */
class PolicyInformationTest extends PHPUnit_Framework_TestCase
{
    const OID = "1.3.6.1.3";
    
    public function testCreateWithCPS()
    {
        $pi = new PolicyInformation(self::OID, new CPSQualifier("urn:test"));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }
    
    /**
     * @depends testCreateWithCPS
     *
     * @param PolicyInformation $pi
     */
    public function testEncodeWithCPS(PolicyInformation $pi)
    {
        $el = $pi->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncodeWithCPS
     *
     * @param string $data
     */
    public function testDecodeWithCPS($data)
    {
        $pi = PolicyInformation::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }
    
    /**
     * @depends testCreateWithCPS
     * @depends testDecodeWithCPS
     *
     * @param PolicyInformation $ref
     * @param PolicyInformation $new
     */
    public function testRecodedWithCPS(PolicyInformation $ref,
        PolicyInformation $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithCPS
     *
     * @param PolicyInformation $pi
     */
    public function testOID(PolicyInformation $pi)
    {
        $this->assertEquals(self::OID, $pi->oid());
    }
    
    /**
     * @depends testCreateWithCPS
     *
     * @param PolicyInformation $pi
     */
    public function testHas(PolicyInformation $pi)
    {
        $this->assertTrue($pi->has(CPSQualifier::OID_CPS));
    }
    
    /**
     * @depends testCreateWithCPS
     *
     * @param PolicyInformation $pi
     */
    public function testHasNot(PolicyInformation $pi)
    {
        $this->assertFalse($pi->has("1.3.6.1.3"));
    }
    
    /**
     * @depends testCreateWithCPS
     *
     * @param PolicyInformation $pi
     */
    public function testGet(PolicyInformation $pi)
    {
        $this->assertInstanceOf(PolicyQualifierInfo::class,
            $pi->get(CPSQualifier::OID_CPS));
    }
    
    /**
     * @depends testCreateWithCPS
     * @expectedException LogicException
     *
     * @param PolicyInformation $pi
     */
    public function testGetFail(PolicyInformation $pi)
    {
        $pi->get("1.3.6.1.3");
    }
    
    /**
     * @depends testCreateWithCPS
     *
     * @param PolicyInformation $pi
     */
    public function testCPSQualifier(PolicyInformation $pi)
    {
        $this->assertInstanceOf(CPSQualifier::class, $pi->CPSQualifier());
    }
    
    /**
     * @depends testCreateWithCPS
     * @expectedException LogicException
     *
     * @param PolicyInformation $pi
     */
    public function testUserNoticeQualifierFail(PolicyInformation $pi)
    {
        $pi->userNoticeQualifier();
    }
    
    public function testCreateWithNotice()
    {
        $pi = new PolicyInformation(self::OID,
            new UserNoticeQualifier(DisplayText::fromString("notice")));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }
    
    /**
     * @depends testCreateWithNotice
     * @expectedException LogicException
     *
     * @param PolicyInformation $pi
     */
    public function testCPSQualifierFail(PolicyInformation $pi)
    {
        $pi->CPSQualifier();
    }
    
    /**
     * @depends testCreateWithNotice
     *
     * @param PolicyInformation $pi
     */
    public function testUserNoticeQualifier(PolicyInformation $pi)
    {
        $this->assertInstanceOf(UserNoticeQualifier::class,
            $pi->userNoticeQualifier());
    }
    
    public function testCreateWithMultiple()
    {
        $pi = new PolicyInformation(self::OID, new CPSQualifier("urn:test"),
            new UserNoticeQualifier(DisplayText::fromString("notice")));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }
    
    /**
     * @depends testCreateWithMultiple
     *
     * @param PolicyInformation $pi
     */
    public function testEncodeWithMultiple(PolicyInformation $pi)
    {
        $el = $pi->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncodeWithMultiple
     *
     * @param string $data
     */
    public function testDecodeWithMultiple($data)
    {
        $pi = PolicyInformation::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }
    
    /**
     * @depends testCreateWithMultiple
     * @depends testDecodeWithMultiple
     *
     * @param PolicyInformation $ref
     * @param PolicyInformation $new
     */
    public function testRecodedMultiple(PolicyInformation $ref,
        PolicyInformation $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithMultiple
     *
     * @param PolicyInformation $pi
     */
    public function testCount(PolicyInformation $pi)
    {
        $this->assertCount(2, $pi);
    }
    
    /**
     * @depends testCreateWithMultiple
     *
     * @param PolicyInformation $pi
     */
    public function testIterator(PolicyInformation $pi)
    {
        $values = array();
        foreach ($pi as $qual) {
            $values[] = $qual;
        }
        $this->assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }
    
    public function testIsAnyPolicy()
    {
        $pi = new PolicyInformation(PolicyInformation::OID_ANY_POLICY);
        $this->assertTrue($pi->isAnyPolicy());
    }
}
