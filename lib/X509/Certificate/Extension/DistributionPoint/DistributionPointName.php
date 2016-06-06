<?php

namespace X509\Certificate\Extension\DistributionPoint;

use ASN1\Element;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\TaggedType;
use X501\ASN1\RDN;
use X509\GeneralName\GeneralNames;


/**
 * Base class for <i>DistributionPointName</i> ASN.1 CHOICE type used by
 * 'CRL Distribution Points' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
abstract class DistributionPointName
{
	const TAG_FULL_NAME = 0;
	const TAG_RDN = 1;
	
	/**
	 * Type.
	 *
	 * @var int $_tag
	 */
	protected $_tag;
	
	/**
	 * Generate ASN.1 element.
	 *
	 * @return Element
	 */
	abstract protected function _valueASN1();
	
	/**
	 * Initialize from TaggedType.
	 *
	 * @param TaggedType $el
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromTaggedType(TaggedType $el) {
		switch ($el->tag()) {
		case self::TAG_FULL_NAME:
			return new FullName(
				GeneralNames::fromASN1(
					$el->asImplicit(Element::TYPE_SEQUENCE)->asSequence()));
		case self::TAG_RDN:
			return new RelativeName(
				RDN::fromASN1($el->asImplicit(Element::TYPE_SET)->asSet()));
		default:
			throw new \UnexpectedValueException(
				"DistributionPointName tag " . $el->tag() . " not supported.");
		}
	}
	
	/**
	 * Get type tag.
	 *
	 * @return int
	 */
	public function tag() {
		return $this->_tag;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return ImplicitlyTaggedType
	 */
	public function toASN1() {
		$element = $this->_valueASN1();
		return new ImplicitlyTaggedType($this->_tag, $element);
	}
}
