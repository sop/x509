<?php
declare(strict_types = 1);

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;
use X509\GeneralName\UniformResourceIdentifier;

/**
 *
 * @group certificate
 * @group extension
 * @group access-description
 */
class SubjectAccessDescriptionTest extends \PHPUnit\Framework\TestCase
{
    const URI = "urn:test";
    public function testCreate()
    {
        $desc = new SubjectAccessDescription(
            SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
            new UniformResourceIdentifier(self::URI));
        $this->assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param SubjectAccessDescription $desc
     */
    public function testEncode(SubjectAccessDescription $desc)
    {
        $el = $desc->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }
    
    /**
     *
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $desc = SubjectAccessDescription::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }
    
    /**
     *
     * @depends testCreate
     * @depends testDecode
     *
     * @param SubjectAccessDescription $ref
     * @param SubjectAccessDescription $new
     */
    public function testRecoded(SubjectAccessDescription $ref,
        SubjectAccessDescription $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param SubjectAccessDescription $desc
     */
    public function testIsCARepository(SubjectAccessDescription $desc)
    {
        $this->assertTrue($desc->isCARepositoryMethod());
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param SubjectAccessDescription $desc
     */
    public function testIsNotTimeStamping(SubjectAccessDescription $desc)
    {
        $this->assertFalse($desc->isTimeStampingMethod());
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param SubjectAccessDescription $desc
     */
    public function testAccessMethod(SubjectAccessDescription $desc)
    {
        $this->assertEquals(SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
            $desc->accessMethod());
    }
    
    /**
     *
     * @depends testCreate
     *
     * @param SubjectAccessDescription $desc
     */
    public function testLocation(SubjectAccessDescription $desc)
    {
        $this->assertEquals(self::URI, $desc->accessLocation()
            ->string());
    }
}
