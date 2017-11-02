<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use X501\ASN1\AttributeTypeAndValue;
use X501\ASN1\RDN;
use X501\ASN1\AttributeValue\CommonNameValue;
use X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use X509\Certificate\Extension\DistributionPoint\FullName;
use X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use X509\Certificate\Extension\DistributionPoint\RelativeName;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 */
class DistributionPointTest extends PHPUnit_Framework_TestCase
{
    public function testCreateWithFullName()
    {
        $dp = new DistributionPoint(FullName::fromURI("urn:test"),
            new ReasonFlags(ReasonFlags::KEY_COMPROMISE),
            new GeneralNames(DirectoryName::fromDNString("cn=Issuer")));
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }
    
    /**
     * @depends testCreateWithFullName
     *
     * @param DistributionPoint $dp
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
     *
     * @param DistributionPoint $ref
     * @param DistributionPoint $new
     */
    public function testRecodedWithFullName(DistributionPoint $ref,
        DistributionPoint $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithFullName
     *
     * @param DistributionPoint $dp
     */
    public function testDistributionPointName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(DistributionPointName::class,
            $dp->distributionPointName());
    }
    
    /**
     * @depends testCreateWithFullName
     *
     * @param DistributionPoint $dp
     */
    public function testFullName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(FullName::class, $dp->fullName());
    }
    
    /**
     * @depends testCreateWithFullName
     * @expectedException LogicException
     *
     * @param DistributionPoint $dp
     */
    public function testRelativeNameFail(DistributionPoint $dp)
    {
        $dp->relativeName();
    }
    
    /**
     * @depends testCreateWithFullName
     *
     * @param DistributionPoint $dp
     */
    public function testReasons(DistributionPoint $dp)
    {
        $this->assertInstanceOf(ReasonFlags::class, $dp->reasons());
    }
    
    /**
     * @depends testCreateWithFullName
     *
     * @param DistributionPoint $dp
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
                        new CommonNameValue("Test")))));
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }
    
    /**
     * @depends testCreateWithRelativeName
     *
     * @param DistributionPoint $dp
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
     *
     * @param DistributionPoint $ref
     * @param DistributionPoint $new
     */
    public function testRecodedWithRelativeName(DistributionPoint $ref,
        DistributionPoint $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithRelativeName
     *
     * @param DistributionPoint $dp
     */
    public function testRelativeName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(RelativeName::class, $dp->relativeName());
    }
    
    /**
     * @depends testCreateWithRelativeName
     * @expectedException LogicException
     *
     * @param DistributionPoint $dp
     */
    public function testFullNameFail(DistributionPoint $dp)
    {
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
     * @expectedException LogicException
     *
     * @param DistributionPoint $dp
     */
    public function testDistributionPointNameFail(DistributionPoint $dp)
    {
        $dp->distributionPointName();
    }
    
    /**
     * @depends testCreateEmpty
     * @expectedException LogicException
     *
     * @param DistributionPoint $dp
     */
    public function testReasonsFail(DistributionPoint $dp)
    {
        $dp->reasons();
    }
    
    /**
     * @depends testCreateEmpty
     * @expectedException LogicException
     *
     * @param DistributionPoint $dp
     */
    public function testCRLIssuerFail(DistributionPoint $dp)
    {
        $dp->crlIssuer();
    }
}
