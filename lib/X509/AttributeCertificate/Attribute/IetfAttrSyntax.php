<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate\Attribute;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\BinaryMatch;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Base class implementing *IetfAttrSyntax* ASN.1 type used by
 * attribute certificate attribute values.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4
 */
abstract class IetfAttrSyntax extends AttributeValue implements \Countable, \IteratorAggregate
{
    /**
     * Policy authority.
     *
     * @var null|GeneralNames
     */
    protected $_policyAuthority;

    /**
     * Values.
     *
     * @var IetfAttrValue[]
     */
    protected $_values;

    /**
     * Constructor.
     */
    public function __construct(IetfAttrValue ...$values)
    {
        $this->_policyAuthority = null;
        $this->_values = $values;
    }

    /**
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        $seq = $el->asSequence();
        $authority = null;
        $idx = 0;
        if ($seq->hasTagged(0)) {
            $authority = GeneralNames::fromASN1(
                $seq->getTagged(0)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
            ++$idx;
        }
        $values = array_map(
            function (UnspecifiedType $el) {
                return IetfAttrValue::fromASN1($el);
            }, $seq->at($idx)->asSequence()->elements());
        $obj = new static(...$values);
        $obj->_policyAuthority = $authority;
        return $obj;
    }

    /**
     * Get self with policy authority.
     */
    public function withPolicyAuthority(GeneralNames $names): self
    {
        $obj = clone $this;
        $obj->_policyAuthority = $names;
        return $obj;
    }

    /**
     * Check whether policy authority is present.
     */
    public function hasPolicyAuthority(): bool
    {
        return isset($this->_policyAuthority);
    }

    /**
     * Get policy authority.
     *
     * @throws \LogicException If not set
     */
    public function policyAuthority(): GeneralNames
    {
        if (!$this->hasPolicyAuthority()) {
            throw new \LogicException('policyAuthority not set.');
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
     * @throws \LogicException If not set
     */
    public function first(): IetfAttrValue
    {
        if (!count($this->_values)) {
            throw new \LogicException('No values.');
        }
        return $this->_values[0];
    }

    public function toASN1(): Element
    {
        $elements = [];
        if (isset($this->_policyAuthority)) {
            $elements[] = new ImplicitlyTaggedType(
                0, $this->_policyAuthority->toASN1());
        }
        $values = array_map(
            function (IetfAttrValue $val) {
                return $val->toASN1();
            }, $this->_values);
        $elements[] = new Sequence(...$values);
        return new Sequence(...$elements);
    }

    public function stringValue(): string
    {
        return '#' . bin2hex($this->toASN1()->toDER());
    }

    public function equalityMatchingRule(): MatchingRule
    {
        return new BinaryMatch();
    }

    public function rfc2253String(): string
    {
        return $this->stringValue();
    }

    /**
     * Get number of values.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_values);
    }

    /**
     * Get iterator for values.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_values);
    }

    protected function _transcodedString(): string
    {
        return $this->stringValue();
    }
}
