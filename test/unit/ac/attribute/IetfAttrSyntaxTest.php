<?php

declare(strict_types=1);

use X501\MatchingRule\MatchingRule;
use X509\AttributeCertificate\Attribute\GroupAttributeValue;
use X509\AttributeCertificate\Attribute\IetfAttrSyntax;

/**
 * @group ac
 * @group attribute
 */
class IetfAttrSyntaxTest extends PHPUnit_Framework_TestCase
{
    public function testCreateEmpty()
    {
        $val = new GroupAttributeValue();
        $this->assertInstanceOf(IetfAttrSyntax::class, $val);
        return $val;
    }
    
    /**
     * @depends testCreateEmpty
     * @expectedException LogicException
     *
     * @param IetfAttrSyntax $val
     */
    public function testNoPolicyAuthorityFail(IetfAttrSyntax $val)
    {
        $val->policyAuthority();
    }
    
    /**
     * @depends testCreateEmpty
     * @expectedException LogicException
     *
     * @param IetfAttrSyntax $val
     */
    public function testNoValuesFirstFail(IetfAttrSyntax $val)
    {
        $val->first();
    }
    
    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testStringValue(IetfAttrSyntax $val)
    {
        $this->assertInternalType("string", $val->stringValue());
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
        $this->assertInternalType("string", $val->rfc2253String());
    }
    
    /**
     * @depends testCreateEmpty
     *
     * @param IetfAttrSyntax $val
     */
    public function testToString(IetfAttrSyntax $val)
    {
        $this->assertInternalType("string", strval($val));
    }
}
