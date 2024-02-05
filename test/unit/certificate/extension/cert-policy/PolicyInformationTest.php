<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use Sop\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 *
 * @internal
 */
class PolicyInformationTest extends TestCase
{
    public const OID = '1.3.6.1.3';

    public function testCreateWithCPS()
    {
        $pi = new PolicyInformation(self::OID, new CPSQualifier('urn:test'));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends testCreateWithCPS
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
     */
    public function testRecodedWithCPS(PolicyInformation $ref,
        PolicyInformation $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testOID(PolicyInformation $pi)
    {
        $this->assertEquals(self::OID, $pi->oid());
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testHas(PolicyInformation $pi)
    {
        $this->assertTrue($pi->has(CPSQualifier::OID_CPS));
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testHasNot(PolicyInformation $pi)
    {
        $this->assertFalse($pi->has('1.3.6.1.3'));
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testGet(PolicyInformation $pi)
    {
        $this->assertInstanceOf(PolicyQualifierInfo::class,
            $pi->get(CPSQualifier::OID_CPS));
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testGetFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->get('1.3.6.1.3');
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testCPSQualifier(PolicyInformation $pi)
    {
        $this->assertInstanceOf(CPSQualifier::class, $pi->CPSQualifier());
    }

    /**
     * @depends testCreateWithCPS
     */
    public function testUserNoticeQualifierFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->userNoticeQualifier();
    }

    public function testCreateWithNotice()
    {
        $pi = new PolicyInformation(self::OID,
            new UserNoticeQualifier(DisplayText::fromString('notice')));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends testCreateWithNotice
     */
    public function testCPSQualifierFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->CPSQualifier();
    }

    /**
     * @depends testCreateWithNotice
     */
    public function testUserNoticeQualifier(PolicyInformation $pi)
    {
        $this->assertInstanceOf(UserNoticeQualifier::class,
            $pi->userNoticeQualifier());
    }

    public function testCreateWithMultiple()
    {
        $pi = new PolicyInformation(self::OID, new CPSQualifier('urn:test'),
            new UserNoticeQualifier(DisplayText::fromString('notice')));
        $this->assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @depends testCreateWithMultiple
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
     */
    public function testRecodedMultiple(PolicyInformation $ref,
        PolicyInformation $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateWithMultiple
     */
    public function testCount(PolicyInformation $pi)
    {
        $this->assertCount(2, $pi);
    }

    /**
     * @depends testCreateWithMultiple
     */
    public function testIterator(PolicyInformation $pi)
    {
        $values = [];
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
