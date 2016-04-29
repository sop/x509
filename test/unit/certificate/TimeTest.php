<?php

use ASN1\Type\Primitive\UTCTime;
use X509\Certificate\Time;


/**
 * @group certificate
 */
class TimeTest extends PHPUnit_Framework_TestCase
{
	const TIME = "2016-04-06 12:00:00";
	
	public function testCreate() {
		$time = Time::fromString(self::TIME);
		$this->assertInstanceOf(Time::class, $time);
		return $time;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Time $time
	 */
	public function testEncode(Time $time) {
		$seq = $time->toASN1();
		$this->assertInstanceOf(UTCTime::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$time = Time::fromASN1(UTCTime::fromDER($der));
		$this->assertInstanceOf(Time::class, $time);
		return $time;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Time $ref
	 * @param Time $new
	 */
	public function testRecoded(Time $ref, Time $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Time $time
	 */
	public function testTime(Time $time) {
		$this->assertEquals(new \DateTimeImmutable(self::TIME), 
			$time->dateTime());
	}
	
	public function testTimezone() {
		$time = Time::fromString(self::TIME, "UTC");
		$this->assertEquals(
			new DateTimeImmutable(self::TIME, new DateTimeZone("UTC")), 
			$time->dateTime());
	}
}
