<?php

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;


/**
 * Base class for <i>PolicyQualifierInfo</i> ASN.1 types used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
abstract class PolicyQualifierInfo
{
	/**
	 * OID for the CPS Pointer qualifier.
	 *
	 * @var string
	 */
	const OID_CPS = "1.3.6.1.5.5.7.2.1";
	
	/**
	 * OID for the user notice qualifier.
	 *
	 * @var string
	 */
	const OID_UNOTICE = "1.3.6.1.5.5.7.2.2";
	
	/**
	 * Qualifier identifier.
	 *
	 * @var string $_oid
	 */
	protected $_oid;
	
	/**
	 * Generate ASN.1 for the 'qualifier' field.
	 *
	 * @return Element
	 */
	abstract protected function _qualifierASN1();
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$oid = $seq->at(0, Element::TYPE_OBJECT_IDENTIFIER)->oid();
		switch ($oid) {
		case self::OID_CPS:
			return CPSQualifier::_fromASN1($seq->at(1, Element::TYPE_STRING));
		case self::OID_UNOTICE:
			return UserNoticeQualifier::_fromASN1(
				$seq->at(1, Element::TYPE_SEQUENCE));
		}
		throw new \UnexpectedValueException("Qualifier $oid not supported.");
	}
	
	/**
	 * Get qualifier identifier.
	 *
	 * @return string
	 */
	public function oid() {
		return $this->_oid;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence(new ObjectIdentifier($this->_oid), 
			$this->_qualifierASN1());
	}
}
