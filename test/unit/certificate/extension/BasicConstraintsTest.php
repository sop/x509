<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extensions;
use X509\Certificate\Extension\BasicConstraintsExtension;
use X509\Certificate\Extension\Extension;

/**
 * @group certificate
 * @group extension
 */
class BasicConstraintsTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $ext = new BasicConstraintsExtension(true, true, 3);
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_BASIC_CONSTRAINTS, $ext->oid());
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
        $ext = BasicConstraintsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
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
     * @param BasicConstraintsExtension $ext
     */
    public function testCA(BasicConstraintsExtension $ext)
    {
        $this->assertTrue($ext->isCA());
    }
    
    /**
     * @depends testCreate
     *
     * @param BasicConstraintsExtension $ext
     */
    public function testPathLen(BasicConstraintsExtension $ext)
    {
        $this->assertEquals(3, $ext->pathLen());
    }
    
    /**
     * @depends testCreate
     *
     * @param BasicConstraintsExtension $ext
     */
    public function testExtensions(BasicConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasBasicConstraints());
        return $extensions;
    }
    
    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->basicConstraints();
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
    }
    
    /**
     * @expectedException LogicException
     */
    public function testNoPathLenFail()
    {
        $ext = new BasicConstraintsExtension(false, false);
        $ext->pathLen();
    }
}
