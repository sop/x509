<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\Certificate\Extension\Target\Targets;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group target
 *
 * @internal
 */
class TargetsTest extends TestCase
{
    private static $_name;

    private static $_group;

    public static function setUpBeforeClass(): void
    {
        self::$_name = new TargetName(
            new UniformResourceIdentifier('urn:target'));
        self::$_group = new TargetGroup(
            new UniformResourceIdentifier('urn:group'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_name = null;
        self::$_group = null;
    }

    public function testCreate()
    {
        $targets = new Targets(self::$_name, self::$_group);
        $this->assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Targets $targets)
    {
        $el = $targets->toASN1();
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
        $targets = Targets::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Targets $ref, Targets $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testAll(Targets $targets)
    {
        $this->assertContainsOnlyInstancesOf(Target::class, $targets->all());
    }

    /**
     * @depends testCreate
     */
    public function testCount(Targets $targets)
    {
        $this->assertCount(2, $targets);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(Targets $targets)
    {
        $values = [];
        foreach ($targets as $target) {
            $values[] = $target;
        }
        $this->assertContainsOnlyInstancesOf(Target::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testHasTarget(Targets $targets)
    {
        $this->assertTrue($targets->hasTarget(self::$_name));
    }

    /**
     * @depends testCreate
     */
    public function testHasNoTarget(Targets $targets)
    {
        $this->assertFalse(
            $targets->hasTarget(new TargetName(new DNSName('nope'))));
    }
}
