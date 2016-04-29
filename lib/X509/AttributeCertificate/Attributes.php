<?php

namespace X509\AttributeCertificate;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use X501\ASN1\Attribute;
use X501\ASN1\AttributeType;
use X501\ASN1\AttributeValue\AttributeValue;
use X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use X509\AttributeCertificate\Attribute\AuthenticationInfoAttributeValue;
use X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
use X509\AttributeCertificate\Attribute\GroupAttributeValue;
use X509\AttributeCertificate\Attribute\RoleAttributeValue;
use X509\Feature\AttributeContainer;


/**
 * Implements <i>Attributes</i> ASN.1 type as a <i>SEQUENCE OF Attribute</i>.
 *
 * Used in <i>AttributeCertificateInfo</i>.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.1
 * @link https://tools.ietf.org/html/rfc5755#section-4.2.7
 */
class Attributes implements \Countable, \IteratorAggregate
{
	use AttributeContainer;
	
	/**
	 * Mapping from OID to attribute value class name.
	 *
	 * @var array
	 */
	private static $_oidToCls = array(
		/* @formatter:off */
		AttributeType::OID_ACCESS_IDENTITY => AccessIdentityAttributeValue::class,
		AttributeType::OID_AUTHENTICATION_INFO => AuthenticationInfoAttributeValue::class,
		AttributeType::OID_CHARGING_IDENTITY => ChargingIdentityAttributeValue::class,
		AttributeType::OID_GROUP => GroupAttributeValue::class,
		AttributeType::OID_ROLE => RoleAttributeValue::class
		/* @formatter:on */
	);
	
	/**
	 * Constructor
	 *
	 * @param Attribute ...$attribs
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
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$attribs = array_map(
			function (Element $el) {
				return Attribute::fromASN1(
					$el->expectType(Element::TYPE_SEQUENCE));
			}, $seq->elements());
		// cast attributes
		$attribs = array_map(
			function (Attribute $attr) {
				$oid = $attr->oid();
				if (isset(self::$_oidToCls[$oid])) {
					$cls = self::$_oidToCls[$oid];
					$attr = $attr->castValues($cls);
				}
				return $attr;
			}, $attribs);
		return new self(...$attribs);
	}
	
	/**
	 * Check whether 'Access Identity' attribute is present.
	 *
	 * @return bool
	 */
	public function hasAccessIdentity() {
		return $this->has(AttributeType::OID_ACCESS_IDENTITY);
	}
	
	/**
	 * Get the first 'Access Identity' attribute value.
	 *
	 * @return AccessIdentityAttributeValue
	 */
	public function accessIdentity() {
		return $this->firstOf(AttributeType::OID_ACCESS_IDENTITY)->first();
	}
	
	/**
	 * Check whether 'Service Authentication Information' attribute is present.
	 *
	 * @return bool
	 */
	public function hasAuthenticationInformation() {
		return $this->has(AttributeType::OID_AUTHENTICATION_INFO);
	}
	
	/**
	 * Get the first 'Service Authentication Information' attribute value.
	 *
	 * @return AuthenticationInfoAttributeValue
	 */
	public function authenticationInformation() {
		return $this->firstOf(AttributeType::OID_AUTHENTICATION_INFO)->first();
	}
	
	/**
	 * Check whether 'Charging Identity' attribute is present.
	 *
	 * @return bool
	 */
	public function hasChargingIdentity() {
		return $this->has(AttributeType::OID_CHARGING_IDENTITY);
	}
	
	/**
	 * Get the first 'Charging Identity' attribute value.
	 *
	 * @return ChargingIdentityAttributeValue
	 */
	public function chargingIdentity() {
		return $this->firstOf(AttributeType::OID_CHARGING_IDENTITY)->first();
	}
	
	/**
	 * Check whether 'Group' attribute is present.
	 *
	 * @return bool
	 */
	public function hasGroup() {
		return $this->has(AttributeType::OID_GROUP);
	}
	
	/**
	 * Get the first 'Group' attribute value.
	 *
	 * @return GroupAttributeValue
	 */
	public function group() {
		return $this->firstOf(AttributeType::OID_GROUP)->first();
	}
	
	/**
	 * Check whether 'Role' attribute is present.
	 *
	 * @return bool
	 */
	public function hasRole() {
		return $this->has(AttributeType::OID_ROLE);
	}
	
	/**
	 * Get the first 'Role' attribute value.
	 *
	 * @return RoleAttributeValue
	 */
	public function role() {
		return $this->firstOf(AttributeType::OID_ROLE)->first();
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array_map(
			function (Attribute $attr) {
				return $attr->toASN1();
			}, array_values($this->_attributes));
		return new Sequence(...$elements);
	}
}
