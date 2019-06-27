<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class SubjectDirectoryAttributesTest extends TestCase
{
    const CN = 'Test';

    const DESC = 'Description';

    public function testCreate()
    {
        $cn = new CommonNameValue(self::CN);
        $desc = new DescriptionValue(self::DESC);
        $ext = new SubjectDirectoryAttributesExtension(false, $cn->toAttribute(),
            $desc->toAttribute());
        $this->assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES,
            $ext->oid());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testCritical(Extension $ext)
    {
        $this->assertFalse($ext->isCritical());
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
        $ext = SubjectDirectoryAttributesExtension::fromASN1(
            Sequence::fromDER($der));
        $this->assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
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
     * @param SubjectDirectoryAttributesExtension $ext
     */
    public function testCN(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertEquals(self::CN,
            $ext->firstOf(AttributeType::OID_COMMON_NAME)
                ->first()
                ->stringValue());
    }

    /**
     * @depends testCreate
     *
     * @param SubjectDirectoryAttributesExtension $ext
     */
    public function testDesc(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertEquals(self::DESC,
            $ext->firstOf(AttributeType::OID_DESCRIPTION)
                ->first()
                ->stringValue());
    }

    /**
     * @depends testCreate
     */
    public function testHas(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertTrue($ext->has('cn'));
    }

    /**
     * @depends testCreate
     */
    public function testHasNot(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertFalse($ext->has('ou'));
    }

    /**
     * @depends testCreate
     */
    public function testAllOf(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(1, $ext->allOf('cn'));
    }

    /**
     * @depends testCreate
     */
    public function testAllOfNone(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(0, $ext->allOf('ou'));
    }

    /**
     * @depends testCreate
     */
    public function testAll(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(2, $ext->all());
    }

    /**
     * @depends testCreate
     *
     * @param SubjectDirectoryAttributesExtension $ext
     */
    public function testCount(SubjectDirectoryAttributesExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends testCreate
     *
     * @param SubjectDirectoryAttributesExtension $ext
     */
    public function testIterator(SubjectDirectoryAttributesExtension $ext)
    {
        $values = [];
        foreach ($ext as $attr) {
            $values[] = $attr;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    public function testEncodeEmptyFail()
    {
        $ext = new SubjectDirectoryAttributesExtension(false);
        $this->expectException(\LogicException::class);
        $ext->toASN1();
    }

    public function testDecodeEmptyFail()
    {
        $seq = new Sequence();
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES),
            new OctetString($seq->toDER()));
        $this->expectException(\UnexpectedValueException::class);
        SubjectDirectoryAttributesExtension::fromASN1($ext_seq);
    }
}
