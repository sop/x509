<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Validity;


/**
 * @group certificate
 * @group time
 */
class ValidityTest extends PHPUnit_Framework_TestCase
{
	const NB = "2016-04-06 12:00:00";
	const NA = "2016-04-06 13:00:00";
	
	public function testCreate() {
		$validity = Validity::fromStrings(self::NB, self::NA);
		$this->assertInstanceOf(Validity::class, $validity);
		return $validity;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Validity $validity
	 */
	public function testEncode(Validity $validity) {
		$seq = $validity->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$validity = Validity::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(Validity::class, $validity);
		return $validity;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Validity $ref
	 * @param Validity $new
	 */
	public function testRecoded(Validity $ref, Validity $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Validity $validity
	 */
	public function testNotBefore(Validity $validity) {
		$this->assertEquals(new \DateTimeImmutable(self::NB), 
			$validity->notBefore()
				->dateTime());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Validity $validity
	 */
	public function testNotAfter(Validity $validity) {
		$this->assertEquals(new \DateTimeImmutable(self::NA), 
			$validity->notAfter()
				->dateTime());
	}
}
