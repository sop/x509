<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use X501\ASN1\Attribute;
use X509\Feature\AttributeContainer;

/**
 * Implements 'Subject Directory Attributes' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.8
 */
class SubjectDirectoryAttributesExtension extends Extension implements 
    \Countable,
    \IteratorAggregate
{
    use AttributeContainer;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param Attribute ...$attribs One or more Attribute objects
     */
    public function __construct(bool $critical, Attribute ...$attribs)
    {
        parent::__construct(self::OID_SUBJECT_DIRECTORY_ATTRIBUTES, $critical);
        $this->_attributes = $attribs;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER(string $data, bool $critical): self
    {
        $attribs = array_map(
            function (UnspecifiedType $el) {
                return Attribute::fromASN1($el->asSequence());
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        if (!count($attribs)) {
            throw new \UnexpectedValueException(
                "SubjectDirectoryAttributes must have at least one Attribute.");
        }
        return new self($critical, ...$attribs);
    }
    
    /**
     *
     * {@inheritdoc}
     * @return Sequence
     */
    protected function _valueASN1(): Sequence
    {
        if (!count($this->_attributes)) {
            throw new \LogicException("No attributes");
        }
        $elements = array_map(
            function (Attribute $attr) {
                return $attr->toASN1();
            }, array_values($this->_attributes));
        return new Sequence(...$elements);
    }
}
