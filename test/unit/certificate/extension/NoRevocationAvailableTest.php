<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\NoRevocationAvailableExtension;

/**
 * @group certificate
 * @group extension
 */
class NoRevocationAvailableTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $ext = new NoRevocationAvailableExtension(true);
        $this->assertInstanceOf(NoRevocationAvailableExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_NO_REV_AVAIL, $ext->oid());
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
        $ext = NoRevocationAvailableExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(NoRevocationAvailableExtension::class, $ext);
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
}
