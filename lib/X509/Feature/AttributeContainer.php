<?php

declare(strict_types = 1);

namespace Sop\X509\Feature;

use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;

/**
 * Trait for objects containing X.501 attributes.
 *
 * Implements methods for Countable and IteratorAggregate interfaces.
 */
trait AttributeContainer
{
    /**
     * Array of attributes.
     *
     * @var Attribute[]
     */
    protected $_attributes;

    /**
     * Check whether attribute is present.
     *
     * @param string $name OID or attribute name
     *
     * @return bool
     */
    public function has(string $name): bool
    {
        return null !== $this->_findFirst($name);
    }

    /**
     * Get first attribute by OID or attribute name.
     *
     * @param string $name OID or attribute name
     *
     * @throws \OutOfBoundsException
     *
     * @return Attribute
     */
    public function firstOf(string $name): Attribute
    {
        $attr = $this->_findFirst($name);
        if (!$attr) {
            throw new \UnexpectedValueException("No {$name} attribute.");
        }
        return $attr;
    }

    /**
     * Get all attributes of given name.
     *
     * @param string $name OID or attribute name
     *
     * @return Attribute[]
     */
    public function allOf(string $name): array
    {
        $oid = AttributeType::attrNameToOID($name);
        $attrs = array_filter($this->_attributes,
            function (Attribute $attr) use ($oid) {
                return $attr->oid() === $oid;
            });
        return array_values($attrs);
    }

    /**
     * Get all attributes.
     *
     * @return Attribute[]
     */
    public function all(): array
    {
        return $this->_attributes;
    }

    /**
     * Get self with additional attributes added.
     *
     * @param Attribute ...$attribs
     *
     * @return self
     */
    public function withAdditional(Attribute ...$attribs): self
    {
        $obj = clone $this;
        foreach ($attribs as $attr) {
            $obj->_attributes[] = $attr;
        }
        return $obj;
    }

    /**
     * Get self with single unique attribute added.
     *
     * All previous attributes of the same type are removed.
     *
     * @param Attribute $attr
     *
     * @return self
     */
    public function withUnique(Attribute $attr): self
    {
        $obj = clone $this;
        $obj->_attributes = array_filter($obj->_attributes,
            function (Attribute $a) use ($attr) {
                return $a->oid() !== $attr->oid();
            });
        $obj->_attributes[] = $attr;
        return $obj;
    }

    /**
     * Get number of attributes.
     *
     * @see \Countable::count()
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->_attributes);
    }

    /**
     * Get iterator for attributes.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_attributes);
    }

    /**
     * Find first attribute of given name or OID.
     *
     * @param string $name
     *
     * @return null|Attribute
     */
    protected function _findFirst(string $name): ?Attribute
    {
        $oid = AttributeType::attrNameToOID($name);
        foreach ($this->_attributes as $attr) {
            if ($attr->oid() === $oid) {
                return $attr;
            }
        }
        return null;
    }
}
