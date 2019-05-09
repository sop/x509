<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrSyntax;

/**
 * @group ac
 * @group attribute
 *
 * @internal
 */
class IetfAttrSyntaxTest extends TestCase
{
    public function testCreateEmpty()
    {
        $val = new GroupAttributeValue();
        $this->assertInstanceOf(IetfAttrSyntax::class, $val);
        return $val;
    }

    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testNoPolicyAuthorityFail(IetfAttrSyntax $val)
    {
        $this->expectException(\LogicException::class);
        $val->policyAuthority();
    }

    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testNoValuesFirstFail(IetfAttrSyntax $val)
    {
        $this->expectException(\LogicException::class);
        $val->first();
    }

    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testStringValue(IetfAttrSyntax $val)
    {
        $this->assertIsString($val->stringValue());
    }

    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testEqualityMatchingRule(IetfAttrSyntax $val)
    {
        $this->assertInstanceOf(MatchingRule::class,
            $val->equalityMatchingRule());
    }

    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testRFC2253String(IetfAttrSyntax $val)
    {
        $this->assertIsString($val->rfc2253String());
    }

    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testToString(IetfAttrSyntax $val)
    {
        $this->assertIsString(strval($val));
    }
}
