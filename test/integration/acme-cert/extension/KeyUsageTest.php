<?php

declare(strict_types = 1);

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefKeyUsageTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return KeyUsageExtension
     */
    public function testKeyUsage()
    {
        $ext = self::$_extensions->get(Extension::OID_KEY_USAGE);
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testKeyUsage
     *
     * @param KeyUsageExtension $ku
     */
    public function testKeyUsageBits(KeyUsageExtension $ku)
    {
        $this->assertFalse($ku->isDigitalSignature());
        $this->assertFalse($ku->isNonRepudiation());
        $this->assertTrue($ku->isKeyEncipherment());
        $this->assertFalse($ku->isDataEncipherment());
        $this->assertFalse($ku->isKeyAgreement());
        $this->assertTrue($ku->isKeyCertSign());
        $this->assertFalse($ku->isCRLSign());
        $this->assertFalse($ku->isEncipherOnly());
        $this->assertFalse($ku->isDecipherOnly());
    }
}
