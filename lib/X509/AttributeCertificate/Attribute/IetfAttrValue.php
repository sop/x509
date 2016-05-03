<?php

namespace X509\AttributeCertificate\Attribute;

use ASN1\Element;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\OctetString;
use ASN1\Type\Primitive\UTF8String;


/**
 * Implements <i>IetfAttrSyntax.values</i> ASN.1 CHOICE type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4
 */
class IetfAttrValue
{
	/**
	 * Element type tag.
	 *
	 * @var int $_type
	 */
	protected $_type;
	
	/**
	 * Value.
	 *
	 * @var string $_value
	 */
	protected $_value;
	
	/**
	 * Constructor
	 *
	 * @param string $value
	 * @param int $type
	 */
	public function __construct($value, $type) {
		$this->_type = $type;
		$this->_value = $value;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Element $el
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Element $el) {
		switch ($el->tag()) {
		case Element::TYPE_OCTET_STRING:
		case Element::TYPE_UTF8_STRING:
			return new self($el->str(), $el->tag());
		case Element::TYPE_OBJECT_IDENTIFIER:
			return new self($el->oid(), $el->tag());
		}
		throw new \UnexpectedValueException(
			"Type " . Element::tagToName($el->tag()) . " not supported.");
	}
	
	/**
	 * Initialize from octet string.
	 *
	 * @param string $octets
	 * @return self
	 */
	public static function fromOctets($octets) {
		return new self($octets, Element::TYPE_OCTET_STRING);
	}
	
	/**
	 * Initialize from UTF-8 string.
	 *
	 * @param string $str
	 * @return self
	 */
	public static function fromString($str) {
		return new self($str, Element::TYPE_UTF8_STRING);
	}
	
	/**
	 * Initialize from OID.
	 *
	 * @param string $oid
	 * @return self
	 */
	public static function fromOID($oid) {
		return new self($oid, Element::TYPE_OBJECT_IDENTIFIER);
	}
	
	/**
	 * Get type tag.
	 *
	 * @return int
	 */
	public function type() {
		return $this->_type;
	}
	
	/**
	 * Whether value type is octets.
	 *
	 * @return bool
	 */
	public function isOctets() {
		return $this->_type == Element::TYPE_OCTET_STRING;
	}
	
	/**
	 * Whether value type is OID.
	 *
	 * @return bool
	 */
	public function isOID() {
		return $this->_type == Element::TYPE_OBJECT_IDENTIFIER;
	}
	
	/**
	 * Whether value type is string.
	 *
	 * @return bool
	 */
	public function isString() {
		return $this->_type == Element::TYPE_UTF8_STRING;
	}
	
	/**
	 * Get value.
	 *
	 * @return string
	 */
	public function value() {
		return $this->_value;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @throws \LogicException
	 * @return Element
	 */
	public function toASN1() {
		switch ($this->_type) {
		case Element::TYPE_OCTET_STRING:
			return new OctetString($this->_value);
		case Element::TYPE_UTF8_STRING:
			return new UTF8String($this->_value);
		case Element::TYPE_OBJECT_IDENTIFIER:
			return new ObjectIdentifier($this->_value);
		}
		throw new \LogicException(
			"Type " . Element::tagToName($this->_type) . " not supported.");
	}
	
	public function __toString() {
		return $this->_value;
	}
}
