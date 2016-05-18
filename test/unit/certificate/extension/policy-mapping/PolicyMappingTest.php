<?php

use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\PolicyMappings\PolicyMapping;


/**
 * @group certificate
 * @group extension
 * @group policy-mapping
 */
class PolicyMappingTest extends PHPUnit_Framework_TestCase
{
	const ISSUER_POLICY = "1.3.6.1.3.1";
	const SUBJECT_POLICY = "1.3.6.1.3.2";
	
	public function testCreate() {
		$mapping = new PolicyMapping(self::ISSUER_POLICY, self::SUBJECT_POLICY);
		$this->assertInstanceOf(PolicyMapping::class, $mapping);
		return $mapping;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PolicyMapping $mapping
	 */
	public function testEncode(PolicyMapping $mapping) {
		$el = $mapping->toASN1();
		$this->assertInstanceOf(Sequence::class, $el);
		return $el->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$mapping = PolicyMapping::fromASN1(Sequence::fromDER($data));
		$this->assertInstanceOf(PolicyMapping::class, $mapping);
		return $mapping;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param PolicyMapping $ref
	 * @param PolicyMapping $new
	 */
	public function testRecoded(PolicyMapping $ref, PolicyMapping $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PolicyMapping $mapping
	 */
	public function testIssuerDomainPolicy(PolicyMapping $mapping) {
		$this->assertEquals(self::ISSUER_POLICY, $mapping->issuerDomainPolicy());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PolicyMapping $mapping
	 */
	public function testSubjectDomainPolicy(PolicyMapping $mapping) {
		$this->assertEquals(self::SUBJECT_POLICY, 
			$mapping->subjectDomainPolicy());
	}
}
