<?php

declare(strict_types=1);

use X501\MatchingRule\MatchingRule;
use X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use X509\AttributeCertificate\Attribute\SvceAuthInfo;
use X509\GeneralName\DirectoryName;

/**
 * @group ac
 * @group attribute
 */
class SvceAuthInfoTest extends PHPUnit_Framework_TestCase
{
    public function testCreateWithoutAuthInfo()
    {
        $val = new AccessIdentityAttributeValue(
            DirectoryName::fromDNString("cn=Svc"),
            DirectoryName::fromDNString("cn=Ident"));
        $this->assertInstanceOf(SvceAuthInfo::class, $val);
        return $val;
    }
    
    /**
     * @depends testCreateWithoutAuthInfo
     * @expectedException LogicException
     *
     * @param SvceAuthInfo $val
     */
    public function testNoAuthInfoFail(SvceAuthInfo $val)
    {
        $val->authInfo();
    }
    
    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testStringValue(SvceAuthInfo $val)
    {
        $this->assertInternalType("string", $val->stringValue());
    }
    
    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testEqualityMatchingRule(SvceAuthInfo $val)
    {
        $this->assertInstanceOf(MatchingRule::class,
            $val->equalityMatchingRule());
    }
    
    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testRFC2253String(SvceAuthInfo $val)
    {
        $this->assertInternalType("string", $val->rfc2253String());
    }
    
    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testToString(SvceAuthInfo $val)
    {
        $this->assertInternalType("string", strval($val));
    }
}
