<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\X509\Certificate\Extension\UnknownExtension;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class UnknownExtensionTest extends TestCase
{
    /**
     * @return \Sop\X509\Certificate\Extension\UnknownExtension
     */
    public function testCreateWithDER()
    {
        $ext = new UnknownExtension('1.3.6.1.3.1', true, new NullType());
        $this->assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreateWithDER
     *
     * @param UnknownExtension $ext
     */
    public function testExtensionValueDER(UnknownExtension $ext)
    {
        $expect = (new NullType())->toDER();
        $this->assertEquals($expect, $ext->extensionValue());
    }

    /**
     * @return \Sop\X509\Certificate\Extension\UnknownExtension
     */
    public function testCreateFromString()
    {
        $ext = UnknownExtension::fromRawString('1.3.6.1.3.1', true, 'DATA');
        $this->assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreateFromString
     *
     * @param UnknownExtension $ext
     */
    public function testExtensionValueRaw(UnknownExtension $ext)
    {
        $this->assertEquals('DATA', $ext->extensionValue());
    }

    /**
     * @depends testCreateWithDER
     *
     * @param UnknownExtension $ext
     */
    public function testExtensionValueASN1(UnknownExtension $ext)
    {
        $cls = new ReflectionClass(UnknownExtension::class);
        $mtd = $cls->getMethod('_valueASN1');
        $mtd->setAccessible(true);
        $result = $mtd->invoke($ext);
        $this->assertInstanceOf(Element::class, $result);
    }

    /**
     * @depends testCreateFromString
     *
     * @param UnknownExtension $ext
     */
    public function testExtensionValueASN1Fail(UnknownExtension $ext)
    {
        $cls = new ReflectionClass(UnknownExtension::class);
        $mtd = $cls->getMethod('_valueASN1');
        $mtd->setAccessible(true);
        $this->expectException(\RuntimeException::class);
        $mtd->invoke($ext);
    }
}
