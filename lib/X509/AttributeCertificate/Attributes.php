<?php

declare(strict_types = 1);

namespace X509\AttributeCertificate;

use ASN1\Type\UnspecifiedType;
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
     * @internal
     *
     * @var array
     */
    const MAP_OID_TO_CLASS = array(
        /* @formatter:off */
        AccessIdentityAttributeValue::OID => AccessIdentityAttributeValue::class,
        AuthenticationInfoAttributeValue::OID => AuthenticationInfoAttributeValue::class,
        ChargingIdentityAttributeValue::OID => ChargingIdentityAttributeValue::class,
        GroupAttributeValue::OID => GroupAttributeValue::class,
        AttributeType::OID_ROLE => RoleAttributeValue::class
        /* @formatter:on */
    );
    
    /**
     * Constructor.
     *
     * @param Attribute[] $attribs
     */
    public function __construct(Attribute ...$attribs)
    {
        $this->_attributes = $attribs;
    }
    
    /**
     * Initialize from attribute values.
     *
     * @param AttributeValue[] $values
     * @return self
     */
    public static function fromAttributeValues(AttributeValue ...$values): self
    {
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
    public static function fromASN1(Sequence $seq): self
    {
        $attribs = array_map(
            function (UnspecifiedType $el) {
                return Attribute::fromASN1($el->asSequence());
            }, $seq->elements());
        // cast attributes
        $attribs = array_map(
            function (Attribute $attr) {
                $oid = $attr->oid();
                if (array_key_exists($oid, self::MAP_OID_TO_CLASS)) {
                    $cls = self::MAP_OID_TO_CLASS[$oid];
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
    public function hasAccessIdentity(): bool
    {
        return $this->has(AccessIdentityAttributeValue::OID);
    }
    
    /**
     * Get the first 'Access Identity' attribute value.
     *
     * @return AccessIdentityAttributeValue
     */
    public function accessIdentity(): AccessIdentityAttributeValue
    {
        return $this->firstOf(AccessIdentityAttributeValue::OID)->first();
    }
    
    /**
     * Check whether 'Service Authentication Information' attribute is present.
     *
     * @return bool
     */
    public function hasAuthenticationInformation(): bool
    {
        return $this->has(AuthenticationInfoAttributeValue::OID);
    }
    
    /**
     * Get the first 'Service Authentication Information' attribute value.
     *
     * @return AuthenticationInfoAttributeValue
     */
    public function authenticationInformation(): AuthenticationInfoAttributeValue
    {
        return $this->firstOf(AuthenticationInfoAttributeValue::OID)->first();
    }
    
    /**
     * Check whether 'Charging Identity' attribute is present.
     *
     * @return bool
     */
    public function hasChargingIdentity(): bool
    {
        return $this->has(ChargingIdentityAttributeValue::OID);
    }
    
    /**
     * Get the first 'Charging Identity' attribute value.
     *
     * @return ChargingIdentityAttributeValue
     */
    public function chargingIdentity(): ChargingIdentityAttributeValue
    {
        return $this->firstOf(ChargingIdentityAttributeValue::OID)->first();
    }
    
    /**
     * Check whether 'Group' attribute is present.
     *
     * @return bool
     */
    public function hasGroup(): bool
    {
        return $this->has(GroupAttributeValue::OID);
    }
    
    /**
     * Get the first 'Group' attribute value.
     *
     * @return GroupAttributeValue
     */
    public function group(): GroupAttributeValue
    {
        return $this->firstOf(GroupAttributeValue::OID)->first();
    }
    
    /**
     * Check whether 'Role' attribute is present.
     *
     * @return bool
     */
    public function hasRole(): bool
    {
        return $this->has(AttributeType::OID_ROLE);
    }
    
    /**
     * Get the first 'Role' attribute value.
     *
     * @return RoleAttributeValue
     */
    public function role(): RoleAttributeValue
    {
        return $this->firstOf(AttributeType::OID_ROLE)->first();
    }
    
    /**
     * Get all 'Role' attribute values.
     *
     * @return RoleAttributeValue[]
     */
    public function roles(): array
    {
        return array_merge(array(),
            ...array_map(
                function (Attribute $attr) {
                    return $attr->values();
                }, $this->allOf(AttributeType::OID_ROLE)));
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array_map(
            function (Attribute $attr) {
                return $attr->toASN1();
            }, array_values($this->_attributes));
        return new Sequence(...$elements);
    }
}
