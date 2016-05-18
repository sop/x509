<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Target\Target;
use X509\Certificate\Extension\Target\TargetGroup;
use X509\Certificate\Extension\Target\TargetName;
use X509\Certificate\Extension\Target\Targets;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group certificate
 * @group extension
 * @group target
 */
class TargetsTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$targets = new Targets(
			new TargetName(new UniformResourceIdentifier("urn:target")), 
			new TargetGroup(new UniformResourceIdentifier("urn:group")));
		$this->assertInstanceOf(Targets::class, $targets);
		return $targets;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Targets $targets
	 */
	public function testEncode(Targets $targets) {
		$el = $targets->toASN1();
		$this->assertInstanceOf(Sequence::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
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
	public function testRecoded(Targets $ref, Targets $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Targets $targets
	 */
	public function testAll(Targets $targets) {
		$this->assertContainsOnlyInstancesOf(Target::class, $targets->all());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Targets $targets
	 */
	public function testCount(Targets $targets) {
		$this->assertCount(2, $targets);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Targets $targets
	 */
	public function testIterator(Targets $targets) {
		$values = array();
		foreach ($targets as $target) {
			$values[] = $target;
		}
		$this->assertContainsOnlyInstancesOf(Target::class, $values);
	}
}
