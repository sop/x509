<?php
declare(strict_types = 1);

use ASN1\Type\Primitive\NullType;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\UnknownExtension;

/**
 *
 * @group certificate
 * @group extension
 */
class ExtensionTest extends \PHPUnit\Framework\TestCase
{
    /**
     *
     * @expectedException BadMethodCallException
     */
    public function testFromDERBadCall()
    {
        $cls = new ReflectionClass(Extension::class);
        $mtd = $cls->getMethod("_fromDER");
        $mtd->setAccessible(true);
        $mtd->invoke(null, "", false);
    }
    
    /**
     */
    public function testExtensionName()
    {
        $ext = new BasicConstraintsExtension(true, true);
        $this->assertEquals("basicConstraints", $ext->extensionName());
    }
    
    /**
     */
    public function testUnknownExtensionName()
    {
        $ext = new UnknownExtension("1.3.6.1.3", false, new NullType());
        $this->assertEquals("1.3.6.1.3", $ext->extensionName());
    }
    
    /**
     */
    public function testToString()
    {
        $ext = new BasicConstraintsExtension(true, true);
        $this->assertEquals("basicConstraints", $ext);
    }
}
