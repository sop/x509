<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group target
 *
 * @internal
 */
class TargetGroupTest extends TestCase
{
    const URI = 'urn:test';

    public function testCreate()
    {
        $target = new TargetGroup(new UniformResourceIdentifier(self::URI));
        $this->assertInstanceOf(TargetGroup::class, $target);
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
        $target = TargetGroup::fromASN1(TaggedType::fromDER($data));
        $this->assertInstanceOf(TargetGroup::class, $target);
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
        $this->assertEquals(Target::TYPE_GROUP, $target->type());
    }

    /**
     * @depends testCreate
     *
     * @param TargetGroup $target
     */
    public function testName(TargetGroup $target)
    {
        $name = $target->name();
        $this->assertInstanceOf(GeneralName::class, $name);
    }

    /**
     * @depends testCreate
     *
     * @param TargetGroup $target
     */
    public function testString(TargetGroup $target)
    {
        $this->assertIsString($target->string());
    }
}
