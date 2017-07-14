<?php
use ASN1\DERData;
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extensions;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\UnknownExtension;

/**
 * @group certificate
 * @group extension
 */
class ExtensionsTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $exts = new Extensions(
            new UnknownExtension("1.3.6.1.3.1", true, new DERData("\x05\x00")),
            new UnknownExtension("1.3.6.1.3.2", true, new DERData("\x05\x00")));
        $this->assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
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
     *
     * @param Extensions $ref
     * @param Extensions $new
     */
    public function testRecoded(Extensions $ref, Extensions $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
     */
    public function testHas(Extensions $exts)
    {
        $this->assertTrue($exts->has("1.3.6.1.3.1"));
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
     */
    public function testHasNot(Extensions $exts)
    {
        $this->assertFalse($exts->has("1.3.6.1.3.3"));
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
     */
    public function testGet(Extensions $exts)
    {
        $this->assertInstanceOf(Extension::class, $exts->get("1.3.6.1.3.1"));
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param Extensions $exts
     */
    public function testGetFail(Extensions $exts)
    {
        $exts->get("1.3.6.1.3.3");
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
     */
    public function testCount(Extensions $exts)
    {
        $this->assertCount(2, $exts);
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
     */
    public function testIterator(Extensions $exts)
    {
        $values = array();
        foreach ($exts as $ext) {
            $values[] = $ext;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Extension::class, $values);
    }
    
    /**
     * @depends testCreate
     *
     * @param Extensions $exts
     */
    public function testWithExtensions(Extensions $exts)
    {
        static $oid = "1.3.6.1.3.3";
        $exts = $exts->withExtensions(
            new UnknownExtension($oid, true, new DERData("\x05\x00")));
        $this->assertTrue($exts->has($oid));
    }
}
