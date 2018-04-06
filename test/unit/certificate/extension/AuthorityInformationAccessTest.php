<?php
declare(strict_types = 1);

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\AuthorityInformationAccessExtension;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use X509\GeneralName\UniformResourceIdentifier;

/**
 *
 * @group certificate
 * @group extension
 */
class AuthorityInformationAccessTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $ext = new AuthorityInformationAccessExtension(false,
            new AuthorityAccessDescription(
                AuthorityAccessDescription::OID_METHOD_CA_ISSUERS,
                new UniformResourceIdentifier('urn:test')),
            new AuthorityAccessDescription(
                AuthorityAccessDescription::OID_METHOD_OSCP,
                new UniformResourceIdentifier("https://oscp.example.com/")));
        $this->assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
        return $ext;
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_AUTHORITY_INFORMATION_ACCESS,
            $ext->oid());
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testCritical(Extension $ext)
    {
        $this->assertFalse($ext->isCritical());
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testEncode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }
    
    /**
     *
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ext = AuthorityInformationAccessExtension::fromASN1(
            Sequence::fromDER($der));
        $this->assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
        return $ext;
    }
    
    /**
     *
     * @depends testCreate
     * @depends testDecode
     *
     * @param Extension $ref
     * @param Extension $new
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param AuthorityInformationAccessExtension $ext
     */
    public function testAccessDescriptions(
        AuthorityInformationAccessExtension $ext)
    {
        $this->assertContainsOnlyInstancesOf(AuthorityAccessDescription::class,
            $ext->accessDescriptions());
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param AuthorityInformationAccessExtension $ext
     */
    public function testCount(AuthorityInformationAccessExtension $ext)
    {
        $this->assertCount(2, $ext);
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param AuthorityInformationAccessExtension $ext
     */
    public function testIterator(AuthorityInformationAccessExtension $ext)
    {
        $values = array();
        foreach ($ext as $desc) {
            $values[] = $desc;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(AuthorityAccessDescription::class,
            $values);
    }
}
