<?php

declare(strict_types = 1);

use Sop\X509\Certificate\Extension\CRLDistributionPointsExtension;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefCRLDistributionPointsTest extends RefExtTestHelper
{
    /**
     * @return CRLDistributionPointsExtension
     */
    public function testCRLDistributionPointsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_CRL_DISTRIBUTION_POINTS);
        $this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCRLDistributionPointsExtension
     *
     * @return DistributionPoint
     */
    public function testDistributionPoint(CRLDistributionPointsExtension $ext)
    {
        $cdp = $ext->getIterator()[0];
        $this->assertInstanceOf(DistributionPoint::class, $cdp);
        return $cdp;
    }

    /**
     * @depends testDistributionPoint
     *
     * @return FullName
     */
    public function testFullName(DistributionPoint $dp)
    {
        $name = $dp->distributionPointName();
        $this->assertEquals(DistributionPointName::TAG_FULL_NAME, $name->tag());
        return $name;
    }

    /**
     * @depends testFullName
     */
    public function testURI(FullName $name)
    {
        $uri = $name->names()
            ->firstOf(GeneralName::TAG_URI)
            ->uri();
        $this->assertEquals('http://example.com/myca.crl', $uri);
    }

    /**
     * @depends testDistributionPoint
     *
     * @return ReasonFlags
     */
    public function testReasons(DistributionPoint $dp)
    {
        $reasons = $dp->reasons();
        $this->assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends testReasons
     */
    public function testReasonFlags(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isKeyCompromise());
        $this->assertTrue($reasons->isCACompromise());
        $this->assertFalse($reasons->isAffiliationChanged());
        $this->assertFalse($reasons->isSuperseded());
        $this->assertFalse($reasons->isCessationOfOperation());
        $this->assertFalse($reasons->isCertificateHold());
        $this->assertFalse($reasons->isPrivilegeWithdrawn());
        $this->assertFalse($reasons->isAACompromise());
    }

    /**
     * @depends testDistributionPoint
     *
     * @return GeneralNames
     */
    public function testIssuer(DistributionPoint $dp)
    {
        $issuer = $dp->crlIssuer();
        $this->assertInstanceOf(GeneralNames::class, $issuer);
        return $issuer;
    }

    /**
     * @depends testIssuer
     */
    public function testIssuerDirName(GeneralNames $gn)
    {
        $dn = $gn->firstOf(GeneralName::TAG_DIRECTORY_NAME)->dn();
        $this->assertEquals('cn=ACME,o=ACME Ltd.', $dn->toString());
    }
}
