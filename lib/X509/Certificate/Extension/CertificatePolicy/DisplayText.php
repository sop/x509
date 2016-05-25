<?php

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Element;
use ASN1\Type\Primitive\BMPString;
use ASN1\Type\Primitive\IA5String;
use ASN1\Type\Primitive\UTF8String;
use ASN1\Type\Primitive\VisibleString;
use ASN1\Type\StringType;


/**
 * Implements <i>DisplayText</i> ASN.1 CHOICE type used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class DisplayText
{
	/**
	 * Text.
	 *
	 * @var string $_text
	 */
	protected $_text;
	
	/**
	 * Element tag.
	 *
	 * @var int $_tag
	 */
	protected $_tag;
	
	/**
	 * Constructor
	 *
	 * @param string $text
	 * @param int $tag
	 */
	public function __construct($text, $tag) {
		$this->_text = $text;
		$this->_tag = $tag;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param StringType $el
	 * @return self
	 */
	public static function fromASN1(StringType $el) {
		return new self($el->string(), $el->tag());
	}
	
	/**
	 * Initialize from string.
	 *
	 * Determines type tag automatically.
	 *
	 * @param string $str
	 * @return self
	 */
	public static function fromString($str) {
		$tag = self::_determineType($str);
		return new self($str, $tag);
	}
	
	/**
	 * Get the text.
	 *
	 * @return string
	 */
	public function string() {
		return $this->_text;
	}
	
	/**
	 * Generate ASN.1 element.
	 *
	 * @throws \UnexpectedValueException
	 * @return StringType
	 */
	public function toASN1() {
		switch ($this->_tag) {
		case Element::TYPE_IA5_STRING:
			return new IA5String($this->_text);
		case Element::TYPE_VISIBLE_STRING:
			return new VisibleString($this->_text);
		case Element::TYPE_BMP_STRING:
			return new BMPString($this->_text);
		case Element::TYPE_UTF8_STRING:
			return new UTF8String($this->_text);
		default:
			throw new \UnexpectedValueException(
				"Type " . Element::tagToName($this->_tag) . " not supported.");
		}
	}
	
	protected static function _determineType($str) {
		// @todo Support other types
		return Element::TYPE_UTF8_STRING;
	}
	
	public function __toString() {
		return $this->string();
	}
}
