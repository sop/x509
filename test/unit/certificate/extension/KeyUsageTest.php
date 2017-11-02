<?php

declare(strict_types=1);

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extensions;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\KeyUsageExtension;

/**
 * @group certificate
 * @group extension
 */
class KeyUsageTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $ext = new KeyUsageExtension(true,
            KeyUsageExtension::DIGITAL_SIGNATURE |
                 KeyUsageExtension::KEY_ENCIPHERMENT);
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_KEY_USAGE, $ext->oid());
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
        $ext = KeyUsageExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
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
     * @param KeyUsageExtension $ext
     */
    public function testDigitalSignature(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isDigitalSignature());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testNonRepudiation(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isNonRepudiation());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testKeyEncipherment(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isKeyEncipherment());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testDataEncipherment(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isDataEncipherment());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testKeyAgreement(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isKeyAgreement());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testKeyCertSign(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isKeyCertSign());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testCRLSign(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isCRLSign());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testEncipherOnly(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isEncipherOnly());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testDecipherOnly(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isDecipherOnly());
    }
    
    /**
     * @depends testCreate
     *
     * @param KeyUsageExtension $ext
     */
    public function testExtensions(KeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasKeyUsage());
        return $extensions;
    }
    
    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->keyUsage();
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
    }
}
