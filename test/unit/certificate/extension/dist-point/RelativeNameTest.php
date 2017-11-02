<?php

declare(strict_types=1);

use ASN1\Type\TaggedType;
use ASN1\Type\Tagged\ImplicitTagging;
use X501\ASN1\AttributeTypeAndValue;
use X501\ASN1\RDN;
use X501\ASN1\AttributeValue\CommonNameValue;
use X509\Certificate\Extension\DistributionPoint\RelativeName;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 */
class RelativeNameTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $name = new RelativeName(
            new RDN(
                AttributeTypeAndValue::fromAttributeValue(
                    new CommonNameValue("Test"))));
        $this->assertInstanceOf(RelativeName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     *
     * @param RelativeName $name
     */
    public function testEncode(RelativeName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }
    
    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $name = RelativeName::fromTaggedType(TaggedType::fromDER($data));
        $this->assertInstanceOf(RelativeName::class, $name);
        return $name;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param RelativeName $ref
     * @param RelativeName $new
     */
    public function testRecoded(RelativeName $ref, RelativeName $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param RelativeName $name
     */
    public function testRDN(RelativeName $name)
    {
        $rdn = $name->rdn();
        $this->assertInstanceOf(RDN::class, $rdn);
    }
}
