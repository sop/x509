<?php

namespace X509\CertificationRequest;

use ASN1\Element;
use ASN1\Type\Constructed\Set;
use X501\ASN1\Attribute;
use X501\ASN1\AttributeValue\AttributeValue;
use X509\CertificationRequest\Attribute\ExtensionRequestValue;
use X509\Feature\AttributeContainer;


/**
 * Implements <i>Attributes</i> ASN.1 type as a <i>SET OF Attribute</i>.
 *
 * Used in <i>CertificationRequestInfo</i>.
 *
 * @link https://tools.ietf.org/html/rfc2986#section-4
 */
class Attributes implements \Countable, \IteratorAggregate
{
	use AttributeContainer;
	
	/**
	 * Mapping from OID to attribute value class name.
	 *
	 * @var array
	 */
	const OID_TO_CLS = array(
		/* @formatter:off */
		ExtensionRequestValue::OID => ExtensionRequestValue::class
		/* @formatter:on */
	);
	
	/**
	 * Constructor
	 *
	 * @param Attribute ...$attribs Attribute objects
	 */
	public function __construct(Attribute ...$attribs) {
		$this->_attributes = $attribs;
	}
	
	/**
	 * Initialize from attribute values.
	 *
	 * @param AttributeValue ...$values
	 * @return self
	 */
	public static function fromAttributeValues(AttributeValue ...$values) {
		$attribs = array_map(
			function (AttributeValue $value) {
				return $value->toAttribute();
			}, $values);
		return new self(...$attribs);
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Set $set
	 * @return self
	 */
	public static function fromASN1(Set $set) {
		$attribs = array_map(
			function (Element $el) {
				return Attribute::fromASN1(
					$el->expectType(Element::TYPE_SEQUENCE));
			}, $set->elements());
		// cast attributes
		$attribs = array_map(
			function (Attribute $attr) {
				$oid = $attr->oid();
				if (array_key_exists($oid, self::OID_TO_CLS)) {
					$cls = self::OID_TO_CLS[$oid];
					$attr = $attr->castValues($cls);
				}
				return $attr;
			}, $attribs);
		return new self(...$attribs);
	}
	
	/**
	 * Check whether extension request attribute is present.
	 *
	 * @return bool
	 */
	public function hasExtensionRequest() {
		return $this->has(ExtensionRequestValue::OID);
	}
	
	/**
	 * Get extension request attribute value.
	 *
	 * @throws \LogicException
	 * @return ExtensionRequestValue
	 */
	public function extensionRequest() {
		if (!$this->hasExtensionRequest()) {
			throw new \LogicException("No extension request attribute.");
		}
		return $this->firstOf(ExtensionRequestValue::OID)->first();
	}
	
	/**
	 * Generate ASN1 structure
	 *
	 * @return Set
	 */
	public function toASN1() {
		$elements = array_map(
			function (Attribute $attr) {
				return $attr->toASN1();
			}, array_values($this->_attributes));
		$set = new Set(...$elements);
		return $set->sortedSetOf();
	}
}
