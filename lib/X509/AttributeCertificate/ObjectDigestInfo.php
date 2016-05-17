<?php

namespace X509\AttributeCertificate;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\Enumerated;
use ASN1\Type\Primitive\ObjectIdentifier;
use CryptoUtil\ASN1\AlgorithmIdentifier;


/**
 * Implements <i>ObjectDigestInfo</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.1
 * @link https://tools.ietf.org/html/rfc5755#section-7.3
 */
class ObjectDigestInfo
{
	const TYPE_PUBLIC_KEY = 0;
	const TYPE_PUBLIC_KEY_CERT = 1;
	const TYPE_OTHER_OBJECT_TYPES = 2;
	
	/**
	 * Object type.
	 *
	 * @var int $_digestedObjectType
	 */
	protected $_digestedObjectType;
	
	/**
	 * OID of other object type.
	 *
	 * @var string|null $_otherObjectTypeID
	 */
	protected $_otherObjectTypeID;
	
	/**
	 * Digest algorithm.
	 *
	 * @var AlgorithmIdentifier $_digestAlgorithm
	 */
	protected $_digestAlgorithm;
	
	/**
	 * Object digest.
	 *
	 * @var BitString $_objectDigest
	 */
	protected $_objectDigest;
	
	/**
	 * Constructor
	 *
	 * @param int $type
	 * @param AlgorithmIdentifier $algo
	 * @param BitString $digest
	 */
	public function __construct($type, AlgorithmIdentifier $algo, 
			BitString $digest) {
		$this->_digestedObjectType = $type;
		$this->_otherObjectTypeID = null;
		$this->_digestAlgorithm = $algo;
		$this->_objectDigest = $digest;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$type = $seq->at(0, Element::TYPE_ENUMERATED)->number();
		$oid = null;
		$idx = 1;
		if ($seq->has($idx, Element::TYPE_OBJECT_IDENTIFIER)) {
			$oid = $seq->at($idx++)->oid();
		}
		$algo = AlgorithmIdentifier::fromASN1(
			$seq->at($idx++, Element::TYPE_SEQUENCE));
		$digest = $seq->at($idx, Element::TYPE_BIT_STRING);
		$obj = new self($type, $algo, $digest);
		$obj->_otherObjectTypeID = $oid;
		return $obj;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array(new Enumerated($this->_digestedObjectType));
		if (isset($this->_otherObjectTypeID)) {
			$elements[] = new ObjectIdentifier($this->_otherObjectTypeID);
		}
		$elements[] = $this->_digestAlgorithm->toASN1();
		$elements[] = $this->_objectDigest;
		return new Sequence(...$elements);
	}
}
