<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationRequest;

use Sop\ASN1\Type\Constructed\Set;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use Sop\X509\Feature\AttributeContainer;

/**
 * Implements <i>Attributes</i> ASN.1 type as a <i>SET OF Attribute</i>.
 *
 * Used in <i>CertificationRequestInfo</i>.
 *
 * @see https://tools.ietf.org/html/rfc2986#section-4
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
    const MAP_OID_TO_CLASS = [
        ExtensionRequestValue::OID => ExtensionRequestValue::class,
    ];

    /**
     * Constructor.
     *
     * @param Attribute ...$attribs Attribute objects
     */
    public function __construct(Attribute ...$attribs)
    {
        $this->_attributes = $attribs;
    }

    /**
     * Initialize from attribute values.
     *
     * @param AttributeValue ...$values
     *
     * @return self
     */
    public static function fromAttributeValues(AttributeValue ...$values): Attributes
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
     * @param Set $set
     *
     * @return self
     */
    public static function fromASN1(Set $set): Attributes
    {
        $attribs = array_map(
            function (UnspecifiedType $el) {
                return Attribute::fromASN1($el->asSequence());
            }, $set->elements());
        // cast attributes
        $attribs = array_map(
            function (Attribute $attr) {
                $oid = $attr->oid();
                if (array_key_exists($oid, self::MAP_OID_TO_CLASS)) {
                    $cls = self::MAP_OID_TO_CLASS[$oid];
                    return $attr->castValues($cls);
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
    public function hasExtensionRequest(): bool
    {
        return $this->has(ExtensionRequestValue::OID);
    }

    /**
     * Get extension request attribute value.
     *
     * @throws \LogicException
     *
     * @return ExtensionRequestValue
     */
    public function extensionRequest(): ExtensionRequestValue
    {
        if (!$this->hasExtensionRequest()) {
            throw new \LogicException('No extension request attribute.');
        }
        return $this->firstOf(ExtensionRequestValue::OID)->first();
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Set
     */
    public function toASN1(): Set
    {
        $elements = array_map(
            function (Attribute $attr) {
                return $attr->toASN1();
            }, array_values($this->_attributes));
        $set = new Set(...$elements);
        return $set->sortedSetOf();
    }
}
