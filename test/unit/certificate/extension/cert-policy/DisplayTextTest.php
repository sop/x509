<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\BaseString;
use Sop\ASN1\Type\Primitive\BMPString;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\Primitive\VisibleString;
use Sop\ASN1\Type\StringType;
use Sop\X509\Certificate\Extension\CertificatePolicy\DisplayText;

/**
 * @group certificate
 * @group extension
 * @group certificate-policy
 *
 * @internal
 */
class DisplayTextTest extends TestCase
{
    public function testCreate()
    {
        $dt = DisplayText::fromString('test');
        $this->assertInstanceOf(DisplayText::class, $dt);
        return $dt;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(DisplayText $dt)
    {
        $el = $dt->toASN1();
        $this->assertInstanceOf(StringType::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $qual = DisplayText::fromASN1(BaseString::fromDER($data));
        $this->assertInstanceOf(DisplayText::class, $qual);
        return $qual;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(DisplayText $ref, DisplayText $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testString(DisplayText $dt)
    {
        $this->assertEquals('test', $dt->string());
    }

    public function testEncodeIA5String()
    {
        $dt = new DisplayText('', Element::TYPE_IA5_STRING);
        $this->assertInstanceOf(IA5String::class, $dt->toASN1());
    }

    public function testEncodeVisibleString()
    {
        $dt = new DisplayText('', Element::TYPE_VISIBLE_STRING);
        $this->assertInstanceOf(VisibleString::class, $dt->toASN1());
    }

    public function testEncodeBMPString()
    {
        $dt = new DisplayText('', Element::TYPE_BMP_STRING);
        $this->assertInstanceOf(BMPString::class, $dt->toASN1());
    }

    public function testEncodeUTF8String()
    {
        $dt = new DisplayText('', Element::TYPE_UTF8_STRING);
        $this->assertInstanceOf(UTF8String::class, $dt->toASN1());
    }

    public function testEncodeUnsupportedTypeFail()
    {
        $dt = new DisplayText('', Element::TYPE_NULL);
        $this->expectException(UnexpectedValueException::class);
        $dt->toASN1();
    }

    /**
     * @depends testCreate
     */
    public function testToString(DisplayText $dt)
    {
        $this->assertIsString(strval($dt));
    }
}
