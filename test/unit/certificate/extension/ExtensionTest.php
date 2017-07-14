<?php
use X509\Certificate\Extension\Extension;

/**
 * @group certificate
 * @group extension
 */
class ExtensionTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException BadMethodCallException
     */
    public function testFromDERBadCall()
    {
        $cls = new ReflectionClass(Extension::class);
        $mtd = $cls->getMethod("_fromDER");
        $mtd->setAccessible(true);
        $mtd->invoke(null, "", false);
    }
}
