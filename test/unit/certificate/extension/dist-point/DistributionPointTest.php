<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\RDN;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\DistributionPoint\RelativeName;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 *
 * @internal
 */
class DistributionPointTest extends TestCase
{
    public function testCreateWithFullName()
    {
        $dp = new DistributionPoint(FullName::fromURI('urn:test'),
            new ReasonFlags(ReasonFlags::KEY_COMPROMISE),
            new GeneralNames(DirectoryName::fromDNString('cn=Issuer')));
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends testCreateWithFullName
     */
    public function testEncodeWithFullName(DistributionPoint $dp)
    {
        $el = $dp->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncodeWithFullName
     *
     * @param string $data
     */
    public function testDecodeWithFullName($data)
    {
        $qual = DistributionPoint::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(DistributionPoint::class, $qual);
        return $qual;
    }

    /**
     * @depends testCreateWithFullName
     * @depends testDecodeWithFullName
     */
    public function testRecodedWithFullName(DistributionPoint $ref,
        DistributionPoint $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateWithFullName
     */
    public function testDistributionPointName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(DistributionPointName::class,
            $dp->distributionPointName());
    }

    /**
     * @depends testCreateWithFullName
     */
    public function testFullName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(FullName::class, $dp->fullName());
    }

    /**
     * @depends testCreateWithFullName
     */
    public function testRelativeNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->relativeName();
    }

    /**
     * @depends testCreateWithFullName
     */
    public function testReasons(DistributionPoint $dp)
    {
        $this->assertInstanceOf(ReasonFlags::class, $dp->reasons());
    }

    /**
     * @depends testCreateWithFullName
     */
    public function testCRLIssuer(DistributionPoint $dp)
    {
        $this->assertInstanceOf(GeneralNames::class, $dp->crlIssuer());
    }

    public function testCreateWithRelativeName()
    {
        $dp = new DistributionPoint(
            new RelativeName(
                new RDN(
                    AttributeTypeAndValue::fromAttributeValue(
                        new CommonNameValue('Test')))));
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends testCreateWithRelativeName
     */
    public function testEncodeWithRelativeName(DistributionPoint $dp)
    {
        $el = $dp->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncodeWithRelativeName
     *
     * @param string $data
     */
    public function testDecodeWithRelativeName($data)
    {
        $qual = DistributionPoint::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(DistributionPoint::class, $qual);
        return $qual;
    }

    /**
     * @depends testCreateWithRelativeName
     * @depends testDecodeWithRelativeName
     */
    public function testRecodedWithRelativeName(DistributionPoint $ref,
        DistributionPoint $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateWithRelativeName
     */
    public function testRelativeName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(RelativeName::class, $dp->relativeName());
    }

    /**
     * @depends testCreateWithRelativeName
     */
    public function testFullNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->fullName();
    }

    public function testCreateEmpty()
    {
        $dp = new DistributionPoint();
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends testCreateEmpty
     */
    public function testDistributionPointNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->distributionPointName();
    }

    /**
     * @depends testCreateEmpty
     */
    public function testReasonsFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->reasons();
    }

    /**
     * @depends testCreateEmpty
     */
    public function testCRLIssuerFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->crlIssuer();
    }
}
