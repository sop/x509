<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class ExtendedKeyUsageTest extends TestCase
{
    public function testCreate()
    {
        $ext = new ExtendedKeyUsageExtension(true,
            ExtendedKeyUsageExtension::OID_SERVER_AUTH,
            ExtendedKeyUsageExtension::OID_CLIENT_AUTH);
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_EXT_KEY_USAGE, $ext->oid());
    }

    /**
     * @depends testCreate
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends testCreate
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
        $ext = ExtendedKeyUsageExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testHas(ExtendedKeyUsageExtension $ext)
    {
        $this->assertTrue(
            $ext->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH,
                ExtendedKeyUsageExtension::OID_CLIENT_AUTH));
    }

    /**
     * @depends testCreate
     */
    public function testHasNot(ExtendedKeyUsageExtension $ext)
    {
        $this->assertFalse(
            $ext->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }

    /**
     * @depends testCreate
     */
    public function testPurposes(ExtendedKeyUsageExtension $ext)
    {
        $this->assertContainsOnly('string', $ext->purposes());
    }

    /**
     * @depends testCreate
     */
    public function testCount(ExtendedKeyUsageExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(ExtendedKeyUsageExtension $ext)
    {
        $values = [];
        foreach ($ext as $oid) {
            $values[] = $oid;
        }
        $this->assertContainsOnly('string', $values);
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(ExtendedKeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasExtendedKeyUsage());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->extendedKeyUsage();
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
    }
}
