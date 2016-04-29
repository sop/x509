<?php

namespace X509\Certificate\Extension\Target;

use ASN1\Element;
use ASN1\Type\TaggedType;


/**
 * Base class for <i>Target</i> ASN.1 CHOICE type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
abstract class Target
{
	const TYPE_NAME = 0;
	const TYPE_GROUP = 1;
	const TYPE_CERT = 2;
	
	/**
	 * Type tag.
	 *
	 * @var int $_type
	 */
	protected $_type;
	
	/**
	 * Generate ASN.1 element.
	 *
	 * @return Element
	 */
	abstract public function toASN1();
	
	/**
	 * Get string value of the target.
	 *
	 * @return string
	 */
	abstract public function string();
	
	/**
	 * Parse concrete type.
	 *
	 * @param TaggedType $el
	 * @return self
	 */
	protected static function _fromASN1(TaggedType $el) {
		// implement in derived class
		throw new \BadMethodCallException();
	}
	
	/**
	 * Parse from ASN.1.
	 *
	 * @param TaggedType $el
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(TaggedType $el) {
		switch ($el->tag()) {
		case self::TYPE_NAME:
			return TargetName::_fromASN1($el->explicit());
		case self::TYPE_GROUP:
			return TargetGroup::_fromASN1($el->explicit());
		case self::TYPE_CERT:
			throw new \RuntimeException("targetCert not supported");
		}
		throw new \UnexpectedValueException("Invalid type");
	}
	
	/**
	 * Get type tag.
	 *
	 * @return int
	 */
	public function type() {
		return $this->_type;
	}
}
