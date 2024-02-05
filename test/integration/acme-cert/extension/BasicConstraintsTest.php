<?php

declare(strict_types = 1);

use Sop\X509\Certificate\Extension\BasicConstraintsExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefBasicConstraintsTest extends RefExtTestHelper
{
    /**
     * @return BasicConstraintsExtension
     */
    public function testBasicConstraintsExtension()
    {
        $ext = self::$_extensions->basicConstraints();
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testBasicConstraintsExtension
     */
    public function testBasicConstraintsCA(BasicConstraintsExtension $bc)
    {
        $this->assertTrue($bc->isCA());
    }

    /**
     * @depends testBasicConstraintsExtension
     */
    public function testBasicConstraintsPathLen(BasicConstraintsExtension $bc)
    {
        $this->assertEquals(3, $bc->pathLen());
    }
}
