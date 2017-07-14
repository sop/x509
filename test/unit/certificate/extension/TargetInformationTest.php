<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\TargetInformationExtension;
use X509\Certificate\Extension\Target\Target;
use X509\Certificate\Extension\Target\TargetGroup;
use X509\Certificate\Extension\Target\TargetName;
use X509\Certificate\Extension\Target\Targets;
use X509\GeneralName\DNSName;
use X509\GeneralName\DirectoryName;

/**
 * @group certificate
 * @group extension
 */
class TargetInformationTest extends PHPUnit_Framework_TestCase
{
    const NAME_DN = "cn=Target";
    
    const GROUP_DOMAIN = ".example.com";
    
    public function testCreateTargets()
    {
        $targets = new Targets(
            new TargetName(DirectoryName::fromDNString(self::NAME_DN)),
            new TargetGroup(new DNSName(self::GROUP_DOMAIN)));
        $this->assertInstanceOf(Targets::class, $targets);
        return $targets;
    }
    
    /**
     * @depends testCreateTargets
     *
     * @param Targets $targets
     */
    public function testCreate(Targets $targets)
    {
        $ext = new TargetInformationExtension(true, $targets);
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_TARGET_INFORMATION, $ext->oid());
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
        $ext = TargetInformationExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
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
     * @param TargetInformationExtension $ext
     */
    public function testCount(TargetInformationExtension $ext)
    {
        $this->assertCount(2, $ext);
    }
    
    /**
     * @depends testCreate
     *
     * @param TargetInformationExtension $ext
     */
    public function testIterator(TargetInformationExtension $ext)
    {
        $values = array();
        foreach ($ext as $target) {
            $values[] = $target;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Target::class, $values);
    }
    
    /**
     * @depends testCreate
     *
     * @param TargetInformationExtension $ext
     */
    public function testName(TargetInformationExtension $ext)
    {
        $this->assertEquals(self::NAME_DN, $ext->names()[0]->string());
    }
    
    /**
     * @depends testCreate
     *
     * @param TargetInformationExtension $ext
     */
    public function testGroup(TargetInformationExtension $ext)
    {
        $this->assertEquals(self::GROUP_DOMAIN, $ext->groups()[0]->string());
    }
    
    /**
     * Cover __clone method.
     *
     * @depends testCreate
     *
     * @param TargetInformationExtension $ext
     */
    public function testClone(TargetInformationExtension $ext)
    {
        $this->assertInstanceOf(TargetInformationExtension::class, clone $ext);
    }
    
    public function testFromTargets()
    {
        $ext = TargetInformationExtension::fromTargets(
            new TargetName(DirectoryName::fromDNString(self::NAME_DN)));
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
    }
}
