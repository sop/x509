<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class InhibitAnyPolicyTest extends TestCase
{
    public function testCreate()
    {
        $ext = new InhibitAnyPolicyExtension(true, 3);
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_INHIBIT_ANY_POLICY, $ext->oid());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
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
        $ext = InhibitAnyPolicyExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
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

    /**
     * @depends testCreate
     *
     * @param InhibitAnyPolicyExtension $ext
     */
    public function testSkipCerts(InhibitAnyPolicyExtension $ext)
    {
        $this->assertEquals(3, $ext->skipCerts());
    }

    /**
     * @depends testCreate
     *
     * @param InhibitAnyPolicyExtension $ext
     */
    public function testExtensions(InhibitAnyPolicyExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasInhibitAnyPolicy());
        return $extensions;
    }

    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->inhibitAnyPolicy();
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
    }
}
