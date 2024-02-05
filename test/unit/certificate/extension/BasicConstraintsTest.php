<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class BasicConstraintsTest extends TestCase
{
    public function testCreate()
    {
        $ext = new BasicConstraintsExtension(true, true, 3);
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_BASIC_CONSTRAINTS, $ext->oid());
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
        $ext = BasicConstraintsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
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
    public function testCA(BasicConstraintsExtension $ext)
    {
        $this->assertTrue($ext->isCA());
    }

    /**
     * @depends testCreate
     */
    public function testPathLen(BasicConstraintsExtension $ext)
    {
        $this->assertEquals(3, $ext->pathLen());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(BasicConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasBasicConstraints());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->basicConstraints();
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
    }

    public function testNoPathLenFail()
    {
        $ext = new BasicConstraintsExtension(false, false);
        $this->expectException(LogicException::class);
        $ext->pathLen();
    }
}
