<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\Attribute;
use Sop\X509\Feature\AttributeContainer;

/**
 * Implements 'Subject Directory Attributes' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.8
 */
class SubjectDirectoryAttributesExtension extends Extension implements \Countable, \IteratorAggregate
{
    use AttributeContainer;

    /**
     * Constructor.
     *
     * @param bool      $critical
     * @param Attribute ...$attribs One or more Attribute objects
     */
    public function __construct(bool $critical, Attribute ...$attribs)
    {
        parent::__construct(self::OID_SUBJECT_DIRECTORY_ATTRIBUTES, $critical);
        $this->_attributes = $attribs;
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $attribs = array_map(
            function (UnspecifiedType $el) {
                return Attribute::fromASN1($el->asSequence());
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        if (!count($attribs)) {
            throw new \UnexpectedValueException(
                'SubjectDirectoryAttributes must have at least one Attribute.');
        }
        return new self($critical, ...$attribs);
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        if (!count($this->_attributes)) {
            throw new \LogicException('No attributes');
        }
        $elements = array_map(
            function (Attribute $attr) {
                return $attr->toASN1();
            }, array_values($this->_attributes));
        return new Sequence(...$elements);
    }
}
