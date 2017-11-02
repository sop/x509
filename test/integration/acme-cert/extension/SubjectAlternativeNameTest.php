<?php

declare(strict_types=1);

use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\SubjectAlternativeNameExtension;
use X509\GeneralName\GeneralName;

require_once __DIR__ . "/RefExtTestHelper.php";

/**
 * @group certificate
 * @group extension
 * @group decode
 */
class RefSubjectAlternativeNameTest extends RefExtTestHelper
{
    /**
     *
     * @param Extensions $extensions
     * @return SubjectAlternativeNameExtension
     */
    public function testSubjectAlternativeName()
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_ALT_NAME);
        $this->assertInstanceOf(SubjectAlternativeNameExtension::class, $ext);
        return $ext;
    }
    
    /**
     * @depends testSubjectAlternativeName
     *
     * @param SubjectAlternativeNameExtension $san
     */
    public function testSANEmail(SubjectAlternativeNameExtension $san)
    {
        $email = $san->names()
            ->firstOf(GeneralName::TAG_RFC822_NAME)
            ->email();
        $this->assertEquals("foo@example.com", $email);
    }
    
    /**
     * @depends testSubjectAlternativeName
     *
     * @param SubjectAlternativeNameExtension $san
     */
    public function testSANURI(SubjectAlternativeNameExtension $san)
    {
        $uri = $san->names()
            ->firstOf(GeneralName::TAG_URI)
            ->uri();
        $this->assertEquals("urn:foo:bar", $uri);
    }
    
    /**
     * @depends testSubjectAlternativeName
     *
     * @param SubjectAlternativeNameExtension $san
     */
    public function testSANDNS(SubjectAlternativeNameExtension $san)
    {
        $name = $san->names()
            ->firstOf(GeneralName::TAG_DNS_NAME)
            ->name();
        $this->assertEquals("alt.example.com", $name);
    }
    
    /**
     * @depends testSubjectAlternativeName
     *
     * @param SubjectAlternativeNameExtension $san
     */
    public function testSANRegisteredID(SubjectAlternativeNameExtension $san)
    {
        $oid = $san->names()
            ->firstOf(GeneralName::TAG_REGISTERED_ID)
            ->oid();
        $this->assertEquals("1.3.6.1.4.1.45710.2.1", $oid);
    }
    
    /**
     * @depends testSubjectAlternativeName
     *
     * @param SubjectAlternativeNameExtension $san
     */
    public function testSANIPAddresses(SubjectAlternativeNameExtension $san)
    {
        $names = $san->names()->allOf(GeneralName::TAG_IP_ADDRESS);
        $ips = array_map(
            function ($name) {
                return $name->address();
            }, $names);
        $this->assertEquals(
            array("127.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"), $ips,
            "", .0, 10, true);
    }
    
    /**
     * @depends testSubjectAlternativeName
     *
     * @param SubjectAlternativeNameExtension $san
     */
    public function testSANDirectoryName(SubjectAlternativeNameExtension $san)
    {
        $dn = $san->names()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        $this->assertEquals("o=ACME Alternative Ltd.,c=FI,cn=alt.example.com",
            $dn);
    }
}
