<?php
declare(strict_types = 1);

use ASN1\Element;
use ASN1\Type\Primitive\NullType;
use X509\Certificate\Extension\UnknownExtension;

/**
 *
 * @group certificate
 * @group extension
 */
class UnknownExtensionTest extends \PHPUnit\Framework\TestCase
{
    /**
     *
     * @return \X509\Certificate\Extension\UnknownExtension
     */
    public function testCreateWithDER()
    {
        $ext = new UnknownExtension('1.3.6.1.3.1', true, new NullType());
        $this->assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }
    
    /**
     *
     * @depends testCreateWithDER
     * @param UnknownExtension $ext
     */
    public function testExtensionValueDER(UnknownExtension $ext)
    {
        $expect = (new NullType())->toDER();
        $this->assertEquals($expect, $ext->extensionValue());
    }
    
    /**
     *
     * @return \X509\Certificate\Extension\UnknownExtension
     */
    public function testCreateFromString()
    {
        $ext = UnknownExtension::fromRawString('1.3.6.1.3.1', true, 'DATA');
        $this->assertInstanceOf(UnknownExtension::class, $ext);
        return $ext;
    }
    
    /**
     *
     * @depends testCreateFromString
     * @param UnknownExtension $ext
     */
    public function testExtensionValueRaw(UnknownExtension $ext)
    {
        $this->assertEquals('DATA', $ext->extensionValue());
    }
    
    /**
     *
     * @depends testCreateWithDER
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
     *
     * @depends testCreateFromString
     * @expectedException RuntimeException
     * @param UnknownExtension $ext
     */
    public function testExtensionValueASN1Fail(UnknownExtension $ext)
    {
        $cls = new ReflectionClass(UnknownExtension::class);
        $mtd = $cls->getMethod('_valueASN1');
        $mtd->setAccessible(true);
        $mtd->invoke($ext);
    }
}
