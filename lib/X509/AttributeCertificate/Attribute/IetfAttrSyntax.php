<?php

declare(strict_types=1);

namespace X509\AttributeCertificate\Attribute;

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X501\ASN1\AttributeValue\AttributeValue;
use X501\MatchingRule\BinaryMatch;
use X509\GeneralName\GeneralNames;

/**
 * Base class implementing <i>IetfAttrSyntax</i> ASN.1 type used by
 * attribute certificate attribute values.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4
 */
abstract class IetfAttrSyntax extends AttributeValue implements 
    \Countable,
    \IteratorAggregate
{
    /**
     * Policy authority.
     *
     * @var GeneralNames|null $_policyAuthority
     */
    protected $_policyAuthority;
    
    /**
     * Values.
     *
     * @var IetfAttrValue[] $_values
     */
    protected $_values;
    
    /**
     * Constructor.
     *
     * @param IetfAttrValue[] $values
     */
    public function __construct(IetfAttrValue ...$values)
    {
        $this->_policyAuthority = null;
        $this->_values = $values;
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el)
    {
        $seq = $el->asSequence();
        $authority = null;
        $idx = 0;
        if ($seq->hasTagged(0)) {
            $authority = GeneralNames::fromASN1(
                $seq->getTagged(0)
                    ->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
            ++$idx;
        }
        $values = array_map(
            function (UnspecifiedType $el) {
                return IetfAttrValue::fromASN1($el);
            },
            $seq->at($idx)
                ->asSequence()
                ->elements());
        $obj = new static(...$values);
        $obj->_policyAuthority = $authority;
        return $obj;
    }
    
    /**
     * Get self with policy authority.
     *
     * @param GeneralNames $names
     * @return self
     */
    public function withPolicyAuthority(GeneralNames $names)
    {
        $obj = clone $this;
        $obj->_policyAuthority = $names;
        return $obj;
    }
    
    /**
     * Check whether policy authority is present.
     *
     * @return bool
     */
    public function hasPolicyAuthority(): bool
    {
        return isset($this->_policyAuthority);
    }
    
    /**
     * Get policy authority.
     *
     * @throws \LogicException
     * @return GeneralNames
     */
    public function policyAuthority(): GeneralNames
    {
        if (!$this->hasPolicyAuthority()) {
            throw new \LogicException("policyAuthority not set.");
        }
        return $this->_policyAuthority;
    }
    
    /**
     * Get values.
     *
     * @return IetfAttrValue[]
     */
    public function values(): array
    {
        return $this->_values;
    }
    
    /**
     * Get first value.
     *
     * @throws \LogicException
     * @return IetfAttrValue
     */
    public function first(): IetfAttrValue
    {
        if (!count($this->_values)) {
            throw new \LogicException("No values.");
        }
        return $this->_values[0];
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::toASN1()
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array();
        if (isset($this->_policyAuthority)) {
            $elements[] = new ImplicitlyTaggedType(0,
                $this->_policyAuthority->toASN1());
        }
        $values = array_map(
            function (IetfAttrValue $val) {
                return $val->toASN1();
            }, $this->_values);
        $elements[] = new Sequence(...$values);
        return new Sequence(...$elements);
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::stringValue()
     * @return string
     */
    public function stringValue(): string
    {
        return "#" . bin2hex($this->toASN1()->toDER());
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::equalityMatchingRule()
     * @return BinaryMatch
     */
    public function equalityMatchingRule(): BinaryMatch
    {
        return new BinaryMatch();
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::rfc2253String()
     * @return string
     */
    public function rfc2253String(): string
    {
        return $this->stringValue();
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::_transcodedString()
     * @return string
     */
    protected function _transcodedString(): string
    {
        return $this->stringValue();
    }
    
    /**
     * Get number of values.
     *
     * @see \Countable::count()
     * @return int
     */
    public function count(): int
    {
        return count($this->_values);
    }
    
    /**
     * Get iterator for values.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_values);
    }
}
