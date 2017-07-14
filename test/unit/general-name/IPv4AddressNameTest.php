<?php
use ASN1\Element;
use ASN1\Type\TaggedType;
use ASN1\Type\Tagged\ImplicitTagging;
use X509\GeneralName\GeneralName;
use X509\GeneralName\IPAddress;
use X509\GeneralName\IPv4Address;

/**
 * @group general-name
 */
class IPv4AddressNameTest extends PHPUnit_Framework_TestCase
{
    const ADDR = "127.0.0.1";
    
    const MASK = "255.255.255.0";
    
    public function testCreate()
    {
        $ip = new IPv4Address(self::ADDR);
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }
    
    /**
     * @depends testCreate
     *
     * @param IPAddress $ip
     */
    public function testEncode(IPAddress $ip)
    {
        $el = $ip->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testChoiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        $this->assertEquals(GeneralName::TAG_IP_ADDRESS, $el->tag());
    }
    
    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param IPAddress $ref
     * @param IPAddress $new
     */
    public function testRecoded(IPAddress $ref, IPAddress $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param IPAddress $ip
     */
    public function testAddress(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR, $ip->address());
    }
    
    public function testCreateWithMask()
    {
        $ip = new IPv4Address(self::ADDR, self::MASK);
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }
    
    /**
     * @depends testCreateWithMask
     *
     * @param IPAddress $ip
     */
    public function testEncodeWithMask(IPAddress $ip)
    {
        $el = $ip->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncodeWithMask
     *
     * @param string $der
     */
    public function testDecodeWithMask($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }
    
    /**
     * @depends testCreateWithMask
     * @depends testDecodeWithMask
     *
     * @param IPAddress $ref
     * @param IPAddress $new
     */
    public function testRecodedWithMask(IPAddress $ref, IPAddress $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreateWithMask
     *
     * @param IPAddress $ip
     */
    public function testMask(IPAddress $ip)
    {
        $this->assertEquals(self::MASK, $ip->mask());
    }
    
    /**
     * @depends testCreateWithMask
     *
     * @param IPAddress $ip
     */
    public function testString(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR . "/" . self::MASK, $ip->string());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidOctetLength()
    {
        IPv4Address::fromOctets("");
    }
}
