<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\RDN;
use Sop\X509\Certificate\Extension\DistributionPoint\RelativeName;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 *
 * @internal
 */
class RelativeNameTest extends TestCase
{
    public function testCreate()
    {
        $name = new RelativeName(
            new RDN(
                AttributeTypeAndValue::fromAttributeValue(
                    new CommonNameValue('Test'))));
        $this->assertInstanceOf(RelativeName::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
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
     */
    public function testRecoded(RelativeName $ref, RelativeName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testRDN(RelativeName $name)
    {
        $rdn = $name->rdn();
        $this->assertInstanceOf(RDN::class, $rdn);
    }
}
