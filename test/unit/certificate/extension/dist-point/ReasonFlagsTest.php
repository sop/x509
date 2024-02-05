<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 *
 * @internal
 */
class ReasonFlagsTest extends TestCase
{
    public const URI = 'urn:test';

    public function testCreate()
    {
        $reasons = new ReasonFlags(
            ReasonFlags::KEY_COMPROMISE | ReasonFlags::AFFILIATION_CHANGED |
                 ReasonFlags::CESSATION_OF_OPERATION |
                 ReasonFlags::PRIVILEGE_WITHDRAWN);
        $this->assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(ReasonFlags $reasons)
    {
        $el = $reasons->toASN1();
        $this->assertInstanceOf(BitString::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $reasons = ReasonFlags::fromASN1(BitString::fromDER($data));
        $this->assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(ReasonFlags $ref, ReasonFlags $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testKeyCompromise(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isKeyCompromise());
    }

    /**
     * @depends testCreate
     */
    public function testCACompromise(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isCACompromise());
    }

    /**
     * @depends testCreate
     */
    public function testAffiliationChanged(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isAffiliationChanged());
    }

    /**
     * @depends testCreate
     */
    public function testSuperseded(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isSuperseded());
    }

    /**
     * @depends testCreate
     */
    public function testCessationOfOperation(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isCessationOfOperation());
    }

    /**
     * @depends testCreate
     */
    public function testCertificateHold(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isCertificateHold());
    }

    /**
     * @depends testCreate
     */
    public function testPriviligeWhitdrawn(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isPrivilegeWithdrawn());
    }

    /**
     * @depends testCreate
     */
    public function testAACompromise(ReasonFlags $reasons)
    {
        $this->assertFalse($reasons->isAACompromise());
    }
}
