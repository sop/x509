<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\FreshestCRLExtension;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class FreshestCRLTest extends TestCase
{
    private static $_dp;

    public static function setUpBeforeClass(): void
    {
        $name = new FullName(
            new GeneralNames(new UniformResourceIdentifier('urn:test')));
        $reasons = new ReasonFlags(ReasonFlags::PRIVILEGE_WITHDRAWN);
        $issuer = new GeneralNames(DirectoryName::fromDNString('cn=Issuer'));
        self::$_dp = new DistributionPoint($name, $reasons, $issuer);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_dp = null;
    }

    public function testCreate()
    {
        $ext = new FreshestCRLExtension(false, self::$_dp);
        $this->assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_FRESHEST_CRL, $ext->oid());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testCritical(Extension $ext)
    {
        $this->assertFalse($ext->isCritical());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
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
        $ext = FreshestCRLExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Extension $ref
     * @param Extension $new
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }
}
