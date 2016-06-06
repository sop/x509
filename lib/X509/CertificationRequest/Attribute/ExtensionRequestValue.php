<?php

namespace X509\CertificationRequest\Attribute;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;
use X501\ASN1\AttributeValue\AttributeValue;
use X501\MatchingRule\BinaryMatch;
use X509\Certificate\Extensions;


/**
 * Implements value for 'Extension request' attribute.
 *
 * @link https://tools.ietf.org/html/rfc2985#page-17
 */
class ExtensionRequestValue extends AttributeValue
{
	const OID = "1.2.840.113549.1.9.14";
	
	/**
	 * Extensions.
	 *
	 * @var Extensions $_extensions
	 */
	protected $_extensions;
	
	/**
	 * Constructor
	 *
	 * @param Extensions $extensions
	 */
	public function __construct(Extensions $extensions) {
		$this->_extensions = $extensions;
		$this->_oid = self::OID;
	}
	
	public static function fromASN1(UnspecifiedType $el) {
		return new self(Extensions::fromASN1($el->asSequence()));
	}
	
	/**
	 * Get requested extensions.
	 *
	 * @return Extensions
	 */
	public function extensions() {
		return $this->_extensions;
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::toASN1()
	 * @return Sequence
	 */
	public function toASN1() {
		return $this->_extensions->toASN1();
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::stringValue()
	 * @return string
	 */
	public function stringValue() {
		return "#" . bin2hex($this->toASN1()->toDER());
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::equalityMatchingRule()
	 * @return BinaryMatch
	 */
	public function equalityMatchingRule() {
		return new BinaryMatch();
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::rfc2253String()
	 * @return string
	 */
	public function rfc2253String() {
		return $this->stringValue();
	}
	
	/**
	 *
	 * @see \X501\ASN1\AttributeValue\AttributeValue::_transcodedString()
	 * @return string
	 */
	protected function _transcodedString() {
		return $this->stringValue();
	}
}
