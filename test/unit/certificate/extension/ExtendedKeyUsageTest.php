<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extensions;
use X509\Certificate\Extension\ExtendedKeyUsageExtension;
use X509\Certificate\Extension\Extension;

/**
 * @group certificate
 * @group extension
 */
class ExtendedKeyUsageTest extends PHPUnit_Framework_TestCase
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
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_EXT_KEY_USAGE, $ext->oid());
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
        $ext = ExtendedKeyUsageExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
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
     * @param ExtendedKeyUsageExtension $ext
     */
    public function testHas(ExtendedKeyUsageExtension $ext)
    {
        $this->assertTrue(
            $ext->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH,
                ExtendedKeyUsageExtension::OID_CLIENT_AUTH));
    }
    
    /**
     * @depends testCreate
     *
     * @param ExtendedKeyUsageExtension $ext
     */
    public function testHasNot(ExtendedKeyUsageExtension $ext)
    {
        $this->assertFalse(
            $ext->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }
    
    /**
     * @depends testCreate
     *
     * @param ExtendedKeyUsageExtension $ext
     */
    public function testPurposes(ExtendedKeyUsageExtension $ext)
    {
        $this->assertContainsOnly("string", $ext->purposes());
    }
    
    /**
     * @depends testCreate
     *
     * @param ExtendedKeyUsageExtension $ext
     */
    public function testCount(ExtendedKeyUsageExtension $ext)
    {
        $this->assertCount(2, $ext);
    }
    
    /**
     * @depends testCreate
     *
     * @param ExtendedKeyUsageExtension $ext
     */
    public function testIterator(ExtendedKeyUsageExtension $ext)
    {
        $values = array();
        foreach ($ext as $oid) {
            $values[] = $oid;
        }
        $this->assertContainsOnly("string", $values);
    }
    
    /**
     * @depends testCreate
     *
     * @param ExtendedKeyUsageExtension $ext
     */
    public function testExtensions(ExtendedKeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasExtendedKeyUsage());
        return $extensions;
    }
    
    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->extendedKeyUsage();
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
    }
}
