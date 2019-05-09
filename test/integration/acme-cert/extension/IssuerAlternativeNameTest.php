<?php

declare(strict_types = 1);

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\IssuerAlternativeNameExtension;
use Sop\X509\GeneralName\GeneralName;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefIssuerAlternativeNameTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return IssuerAlternativeNameExtension
     */
    public function testIssuerAlternativeName()
    {
        $ext = self::$_extensions->get(Extension::OID_ISSUER_ALT_NAME);
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testIssuerAlternativeName
     *
     * @param IssuerAlternativeNameExtension $ian
     */
    public function testIANDirectoryName(IssuerAlternativeNameExtension $ian)
    {
        $dn = $ian->names()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        $this->assertEquals(
            'o=ACME Alternative Ltd.,c=FI,cn=ACME Wheel Intermediate', $dn);
    }
}
