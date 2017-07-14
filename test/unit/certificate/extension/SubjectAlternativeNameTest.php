<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extensions;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\SubjectAlternativeNameExtension;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;

/**
 * @group certificate
 * @group extension
 */
class SubjectAlternativeNameTest extends PHPUnit_Framework_TestCase
{
    const DN = "cn=Alt name";
    
    public function testCreate()
    {
        $ext = new SubjectAlternativeNameExtension(true,
            new GeneralNames(DirectoryName::fromDNString(self::DN)));
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_SUBJECT_ALT_NAME, $ext->oid());
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
        $ext = SubjectAlternativeNameExtension::fromASN1(
            Sequence::fromDER($der));
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
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
     * @param SubjectAlternativeNameExtension $ext
     */
    public function testName(SubjectAlternativeNameExtension $ext)
    {
        $this->assertEquals(self::DN, $ext->names()
            ->firstDN());
    }
    
    /**
     * @depends testCreate
     *
     * @param SubjectAlternativeNameExtension $ext
     */
    public function testExtensions(SubjectAlternativeNameExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasSubjectAlternativeName());
        return $extensions;
    }
    
    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->subjectAlternativeName();
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
    }
}
