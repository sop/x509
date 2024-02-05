<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\DERData;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\UnknownExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class ExtensionsTest extends TestCase
{
    public function testCreate()
    {
        $exts = new Extensions(
            new UnknownExtension('1.3.6.1.3.1', true, new DERData("\x05\x00")),
            new UnknownExtension('1.3.6.1.3.2', true, new DERData("\x05\x00")));
        $this->assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Extensions $exts)
    {
        $seq = $exts->toASN1();
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
        $exts = Extensions::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Extensions $ref, Extensions $new)
    {
        $this->assertEquals($ref->toASN1(), $new->toASN1());
    }

    /**
     * @depends testCreate
     */
    public function testHas(Extensions $exts)
    {
        $this->assertTrue($exts->has('1.3.6.1.3.1'));
    }

    /**
     * @depends testCreate
     */
    public function testHasNot(Extensions $exts)
    {
        $this->assertFalse($exts->has('1.3.6.1.3.3'));
    }

    /**
     * @depends testCreate
     */
    public function testGet(Extensions $exts)
    {
        $this->assertInstanceOf(Extension::class, $exts->get('1.3.6.1.3.1'));
    }

    /**
     * @depends testCreate
     */
    public function testGetFail(Extensions $exts)
    {
        $this->expectException(LogicException::class);
        $exts->get('1.3.6.1.3.3');
    }

    /**
     * @depends testCreate
     */
    public function testCount(Extensions $exts)
    {
        $this->assertCount(2, $exts);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(Extensions $exts)
    {
        $values = [];
        foreach ($exts as $ext) {
            $values[] = $ext;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Extension::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testWithExtensions(Extensions $exts)
    {
        static $oid = '1.3.6.1.3.3';
        $exts = $exts->withExtensions(
            new UnknownExtension($oid, true, new DERData("\x05\x00")));
        $this->assertTrue($exts->has($oid));
    }
}
