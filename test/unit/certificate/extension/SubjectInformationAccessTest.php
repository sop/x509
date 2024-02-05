<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectInformationAccessExtension;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class SubjectInformationAccessTest extends TestCase
{
    public function testCreate()
    {
        $ext = new SubjectInformationAccessExtension(false,
            new SubjectAccessDescription(
                SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
                new UniformResourceIdentifier('urn:test')),
            new SubjectAccessDescription(
                SubjectAccessDescription::OID_METHOD_TIME_STAMPING,
                new UniformResourceIdentifier('https://ts.example.com/')));
        $this->assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_SUBJECT_INFORMATION_ACCESS,
            $ext->oid());
    }

    /**
     * @depends testCreate
     */
    public function testCritical(Extension $ext)
    {
        $this->assertFalse($ext->isCritical());
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
        $ext = SubjectInformationAccessExtension::fromASN1(
            Sequence::fromDER($der));
        $this->assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
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
    public function testAccessDescriptions(
        SubjectInformationAccessExtension $ext)
    {
        $this->assertContainsOnlyInstancesOf(SubjectAccessDescription::class,
            $ext->accessDescriptions());
    }

    /**
     * @depends testCreate
     */
    public function testCount(SubjectInformationAccessExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(SubjectInformationAccessExtension $ext)
    {
        $values = [];
        foreach ($ext as $desc) {
            $values[] = $desc;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(SubjectAccessDescription::class,
            $values);
    }
}
