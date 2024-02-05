<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class SubjectAlternativeNameTest extends TestCase
{
    public const DN = 'cn=Alt name';

    public function testCreate()
    {
        $ext = new SubjectAlternativeNameExtension(true,
            new GeneralNames(DirectoryName::fromDNString(self::DN)));
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_SUBJECT_ALT_NAME, $ext->oid());
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
        $ext = SubjectAlternativeNameExtension::fromASN1(
            Sequence::fromDER($der));
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
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
    public function testName(SubjectAlternativeNameExtension $ext)
    {
        $this->assertEquals(self::DN, $ext->names()
            ->firstDN());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(SubjectAlternativeNameExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasSubjectAlternativeName());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->subjectAlternativeName();
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
    }
}
