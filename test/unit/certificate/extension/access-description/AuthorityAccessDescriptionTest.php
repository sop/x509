<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group access-description
 *
 * @internal
 */
class AuthorityAccessDescriptionTest extends TestCase
{
    const URI = 'urn:test';

    public function testCreate()
    {
        $desc = new AuthorityAccessDescription(
            AuthorityAccessDescription::OID_METHOD_OSCP,
            new UniformResourceIdentifier(self::URI));
        $this->assertInstanceOf(AuthorityAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityAccessDescription $desc
     */
    public function testEncode(AuthorityAccessDescription $desc)
    {
        $el = $desc->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $desc = AuthorityAccessDescription::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(AuthorityAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param AuthorityAccessDescription $ref
     * @param AuthorityAccessDescription $new
     */
    public function testRecoded(AuthorityAccessDescription $ref,
        AuthorityAccessDescription $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityAccessDescription $desc
     */
    public function testIsOSCP(AuthorityAccessDescription $desc)
    {
        $this->assertTrue($desc->isOSCPMethod());
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityAccessDescription $desc
     */
    public function testIsNotCAIssuers(AuthorityAccessDescription $desc)
    {
        $this->assertFalse($desc->isCAIssuersMethod());
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityAccessDescription $desc
     */
    public function testAccessMethod(AuthorityAccessDescription $desc)
    {
        $this->assertEquals(AuthorityAccessDescription::OID_METHOD_OSCP,
            $desc->accessMethod());
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityAccessDescription $desc
     */
    public function testLocation(AuthorityAccessDescription $desc)
    {
        $this->assertEquals(self::URI, $desc->accessLocation()
            ->string());
    }
}
