<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use Sop\X509\Certificate\Extension\CertificatePolicy\NoticeReference;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 *
 * @internal
 */
class NoticeReferenceTest extends TestCase
{
    public function testCreate()
    {
        $ref = new NoticeReference(DisplayText::fromString('org'), 1, 2, 3);
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(NoticeReference $ref)
    {
        $el = $ref->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $ref = NoticeReference::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(NoticeReference $ref, NoticeReference $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testOrganization(NoticeReference $ref)
    {
        $this->assertEquals('org', $ref->organization()
            ->string());
    }

    /**
     * @depends testCreate
     */
    public function testNumbers(NoticeReference $ref)
    {
        $this->assertEquals([1, 2, 3], $ref->numbers());
    }
}
