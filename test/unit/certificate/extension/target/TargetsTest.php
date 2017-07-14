<?php
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Target\Target;
use X509\Certificate\Extension\Target\TargetGroup;
use X509\Certificate\Extension\Target\TargetName;
use X509\Certificate\Extension\Target\Targets;
use X509\GeneralName\DNSName;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * @group certificate
 * @group extension
 * @group target
 */
class TargetsTest extends PHPUnit_Framework_TestCase
{
    private static $_name;
    
    private static $_group;
    
    public static function setUpBeforeClass()
    {
        self::$_name = new TargetName(
            new UniformResourceIdentifier("urn:target"));
        self::$_group = new TargetGroup(
            new UniformResourceIdentifier("urn:group"));
    }
    
    public static function tearDownAfterClass()
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
     *
     * @param Targets $targets
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
     *
     * @param Targets $ref
     * @param Targets $new
     */
    public function testRecoded(Targets $ref, Targets $new)
    {
        $this->assertEquals($ref, $new);
    }
    
    /**
     * @depends testCreate
     *
     * @param Targets $targets
     */
    public function testAll(Targets $targets)
    {
        $this->assertContainsOnlyInstancesOf(Target::class, $targets->all());
    }
    
    /**
     * @depends testCreate
     *
     * @param Targets $targets
     */
    public function testCount(Targets $targets)
    {
        $this->assertCount(2, $targets);
    }
    
    /**
     * @depends testCreate
     *
     * @param Targets $targets
     */
    public function testIterator(Targets $targets)
    {
        $values = array();
        foreach ($targets as $target) {
            $values[] = $target;
        }
        $this->assertContainsOnlyInstancesOf(Target::class, $values);
    }
    
    /**
     * @depends testCreate
     *
     * @param Targets $targets
     */
    public function testHasTarget(Targets $targets)
    {
        $this->assertTrue($targets->hasTarget(self::$_name));
    }
    
    /**
     * @depends testCreate
     *
     * @param Targets $targets
     */
    public function testHasNoTarget(Targets $targets)
    {
        $this->assertFalse(
            $targets->hasTarget(new TargetName(new DNSName("nope"))));
    }
}
