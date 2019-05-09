<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group target
 *
 * @internal
 */
class TargetNameTest extends TestCase
{
    const URI = 'urn:test';

    public function testCreate()
    {
        $target = new TargetName(new UniformResourceIdentifier(self::URI));
        $this->assertInstanceOf(TargetName::class, $target);
        return $target;
    }

    /**
     * @depends testCreate
     *
     * @param Target $target
     */
    public function testEncode(Target $target)
    {
        $el = $target->toASN1();
        $this->assertInstanceOf(ExplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $target = TargetName::fromASN1(TaggedType::fromDER($data));
        $this->assertInstanceOf(TargetName::class, $target);
        return $target;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Target $ref
     * @param Target $new
     */
    public function testRecoded(Target $ref, Target $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param Target $target
     */
    public function testType(Target $target)
    {
        $this->assertEquals(Target::TYPE_NAME, $target->type());
    }

    /**
     * @depends testCreate
     *
     * @param TargetName $target
     */
    public function testName(TargetName $target)
    {
        $name = $target->name();
        $this->assertInstanceOf(GeneralName::class, $name);
    }

    /**
     * @depends testCreate
     *
     * @param TargetName $target
     */
    public function testString(TargetName $target)
    {
        $this->assertIsString($target->string());
    }
}
