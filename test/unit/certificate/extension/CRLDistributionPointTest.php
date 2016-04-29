<?php

use ASN1\Type\Constructed\Sequence;
use X501\ASN1\Name;
use X509\Certificate\Extension\CRLDistributionPointsExtension;
use X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use X509\Certificate\Extension\DistributionPoint\FullName;
use X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use X509\Certificate\Extension\Extension;
use X509\Certificate\Extensions;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;


/**
 * @group certificate
 * @group extension
 */
class CRLDistributionPointTest extends PHPUnit_Framework_TestCase
{
	const DP_URI = "urn:test";
	const ISSUER_DN = "cn=Issuer";
	
	public function testCreateDistributionPoint() {
		$name = new FullName(
			new GeneralNames(new UniformResourceIdentifier(self::DP_URI)));
		$reasons = new ReasonFlags(ReasonFlags::PRIVILEGE_WITHDRAWN);
		$issuer = new GeneralNames(DirectoryName::fromDNString(self::ISSUER_DN));
		$dp = new DistributionPoint($name, $reasons, $issuer);
		$this->assertInstanceOf(DistributionPoint::class, $dp);
		return $dp;
	}
	
	/**
	 * @depends testCreateDistributionPoint
	 *
	 * @param DistributionPoint $dp
	 */
	public function testCreate(DistributionPoint $dp) {
		$ext = new CRLDistributionPointsExtension(true, $dp);
		$this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testOID(Extension $ext) {
		$this->assertEquals(Extension::OID_CRL_DISTRIBUTION_POINTS, $ext->oid());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testCritical(Extension $ext) {
		$this->assertTrue($ext->isCritical());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Extension $ext
	 */
	public function testEncode(Extension $ext) {
		$seq = $ext->toASN1();
		$this->assertInstanceOf(Sequence::class, $seq);
		return $seq->toDER();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $der
	 */
	public function testDecode($der) {
		$ext = CRLDistributionPointsExtension::fromASN1(Sequence::fromDER($der));
		$this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
		return $ext;
	}
	
	/**
	 * @depends testCreate
	 * @depends testDecode
	 *
	 * @param Extension $ref
	 * @param Extension $new
	 */
	public function testRecoded(Extension $ref, Extension $new) {
		$this->assertEquals($ref, $new);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CRLDistributionPointsExtension $ext
	 */
	public function testCount(CRLDistributionPointsExtension $ext) {
		$this->assertCount(1, $ext);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CRLDistributionPointsExtension $ext
	 */
	public function testIterator(CRLDistributionPointsExtension $ext) {
		$values = array();
		foreach ($ext as $dp) {
			$values[] = $dp;
		}
		$this->assertCount(1, $values);
		$this->assertContainsOnlyInstancesOf(DistributionPoint::class, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CRLDistributionPointsExtension $ext
	 */
	public function testDistributionPoint(CRLDistributionPointsExtension $ext) {
		$dp = $ext->distributionPoints()[0];
		$this->assertInstanceOf(DistributionPoint::class, $dp);
		return $dp;
	}
	
	/**
	 * @depends testDistributionPoint
	 *
	 * @param DistributionPoint $dp
	 */
	public function testDPName(DistributionPoint $dp) {
		$uri = $dp->fullName()
			->names()
			->firstURI();
		$this->assertEquals(self::DP_URI, $uri);
	}
	
	/**
	 * @depends testDistributionPoint
	 *
	 * @param DistributionPoint $dp
	 */
	public function testDPReasons(DistributionPoint $dp) {
		$this->assertTrue($dp->reasons()
			->isPrivilegeWithdrawn());
	}
	
	/**
	 * @depends testDistributionPoint
	 *
	 * @param DistributionPoint $dp
	 */
	public function testDPIssuer(DistributionPoint $dp) {
		$this->assertEquals(self::ISSUER_DN, $dp->crlIssuer()
			->firstDN());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CRLDistributionPointsExtension $ext
	 */
	public function testExtensions(CRLDistributionPointsExtension $ext) {
		$extensions = new Extensions($ext);
		$this->assertTrue($extensions->hasCRLDistributionPoints());
		return $extensions;
	}
	
	/**
	 * @depends testExtensions
	 *
	 * @param Extensions $exts
	 */
	public function testFromExtensions(Extensions $exts) {
		$ext = $exts->crlDistributionPoints();
		$this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
	}
}
