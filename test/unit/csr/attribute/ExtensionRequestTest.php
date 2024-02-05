<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\Certificate\Extensions;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;

/**
 * @group csr
 * @group attribute
 *
 * @internal
 */
class ExtensionRequestTest extends TestCase
{
    public function testCreate()
    {
        $value = new ExtensionRequestValue(new Extensions());
        $this->assertInstanceOf(ExtensionRequestValue::class, $value);
        return $value;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(AttributeValue $value)
    {
        $el = $value->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $value = ExtensionRequestValue::fromASN1(
            Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(ExtensionRequestValue::class, $value);
        return $value;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(AttributeValue $ref, AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testOID(AttributeValue $value)
    {
        $this->assertEquals(ExtensionRequestValue::OID, $value->oid());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(ExtensionRequestValue $value)
    {
        $this->assertInstanceOf(Extensions::class, $value->extensions());
    }

    /**
     * @depends testCreate
     */
    public function testStringValue(ExtensionRequestValue $value)
    {
        $this->assertIsString($value->stringValue());
    }

    /**
     * @depends testCreate
     */
    public function testEqualityMatchingRule(ExtensionRequestValue $value)
    {
        $this->assertInstanceOf(MatchingRule::class,
            $value->equalityMatchingRule());
    }

    /**
     * @depends testCreate
     */
    public function testRFC2253String(ExtensionRequestValue $value)
    {
        $this->assertIsString($value->rfc2253String());
    }

    /**
     * @depends testCreate
     */
    public function testToString(ExtensionRequestValue $value)
    {
        $this->assertIsString(strval($value));
    }
}
