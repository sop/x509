<?php

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\UnspecifiedType;


/**
 * Implements <i>PolicyInformation</i> ASN.1 type used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class PolicyInformation implements \Countable, \IteratorAggregate
{
	/**
	 * Wildcard policy.
	 *
	 * @var string
	 */
	const OID_ANY_POLICY = "2.5.29.32.0";
	
	/**
	 * Policy identifier.
	 *
	 * @var string $_oid
	 */
	protected $_oid;
	
	/**
	 * Policy qualifiers.
	 *
	 * @var PolicyQualifierInfo[] $_qualifiers
	 */
	protected $_qualifiers;
	
	/**
	 * Constructor
	 *
	 * @param string $oid
	 * @param PolicyQualifierInfo ...$qualifiers
	 */
	public function __construct($oid, PolicyQualifierInfo ...$qualifiers) {
		$this->_oid = $oid;
		$this->_qualifiers = array();
		foreach ($qualifiers as $qual) {
			$this->_qualifiers[$qual->oid()] = $qual;
		}
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$oid = $seq->at(0)
			->asObjectIdentifier()
			->oid();
		$qualifiers = array();
		if (count($seq) > 1) {
			$qualifiers = array_map(
				function (UnspecifiedType $el) {
					return PolicyQualifierInfo::fromASN1($el->asSequence());
				}, $seq->at(1)
					->asSequence()
					->elements());
		}
		return new self($oid, ...$qualifiers);
	}
	
	/**
	 * Get policy identifier.
	 *
	 * @return string
	 */
	public function oid() {
		return $this->_oid;
	}
	
	/**
	 * Check whether this policy is anyPolicy.
	 *
	 * @return bool
	 */
	public function isAnyPolicy() {
		return self::OID_ANY_POLICY == $this->_oid;
	}
	
	/**
	 * Check whether qualifier is present.
	 *
	 * @param string $oid
	 * @return boolean
	 */
	public function has($oid) {
		return isset($this->_qualifiers[$oid]);
	}
	
	/**
	 * Get qualifier by OID.
	 *
	 * @param string $oid
	 * @throws \OutOfBoundsException
	 * @return PolicyQualifierInfo
	 */
	public function get($oid) {
		if (!$this->has($oid)) {
			throw new \LogicException("No $oid qualifier.");
		}
		return $this->_qualifiers[$oid];
	}
	
	/**
	 * Check whether CPS qualifier is present.
	 *
	 * @return bool
	 */
	public function hasCPSQualifier() {
		return $this->has(PolicyQualifierInfo::OID_CPS);
	}
	
	/**
	 * Get CPS qualifier.
	 *
	 * @throws \LogicException
	 * @return CPSQualifier
	 */
	public function CPSQualifier() {
		if (!$this->hasCPSQualifier()) {
			throw new \LogicException("CPS qualifier not set.");
		}
		return $this->get(PolicyQualifierInfo::OID_CPS);
	}
	
	/**
	 * Check whether user notice qualifier is present.
	 *
	 * @return bool
	 */
	public function hasUserNoticeQualifier() {
		return $this->has(PolicyQualifierInfo::OID_UNOTICE);
	}
	
	/**
	 * Get user notice qualifier.
	 *
	 * @throws \LogicException
	 * @return UserNoticeQualifier
	 */
	public function userNoticeQualifier() {
		if (!$this->hasUserNoticeQualifier()) {
			throw new \LogicException("User notice qualifier not set.");
		}
		return $this->get(PolicyQualifierInfo::OID_UNOTICE);
	}
	
	/**
	 * Get ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array(new ObjectIdentifier($this->_oid));
		if (count($this->_qualifiers)) {
			$qualifiers = array_map(
				function (PolicyQualifierInfo $pqi) {
					return $pqi->toASN1();
				}, array_values($this->_qualifiers));
			$elements[] = new Sequence(...$qualifiers);
		}
		return new Sequence(...$elements);
	}
	
	/**
	 * Get number of qualifiers.
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_qualifiers);
	}
	
	/**
	 * Get iterator for qualifiers.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_qualifiers);
	}
}
