<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class KeyUsageTest extends TestCase
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
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_KEY_USAGE, $ext->oid());
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
        $ext = KeyUsageExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
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
    public function testDigitalSignature(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isDigitalSignature());
    }

    /**
     * @depends testCreate
     */
    public function testNonRepudiation(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isNonRepudiation());
    }

    /**
     * @depends testCreate
     */
    public function testKeyEncipherment(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isKeyEncipherment());
    }

    /**
     * @depends testCreate
     */
    public function testDataEncipherment(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isDataEncipherment());
    }

    /**
     * @depends testCreate
     */
    public function testKeyAgreement(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isKeyAgreement());
    }

    /**
     * @depends testCreate
     */
    public function testKeyCertSign(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isKeyCertSign());
    }

    /**
     * @depends testCreate
     */
    public function testCRLSign(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isCRLSign());
    }

    /**
     * @depends testCreate
     */
    public function testEncipherOnly(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isEncipherOnly());
    }

    /**
     * @depends testCreate
     */
    public function testDecipherOnly(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isDecipherOnly());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(KeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasKeyUsage());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->keyUsage();
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
    }
}
