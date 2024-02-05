<?php

declare(strict_types = 1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\Name;

/**
 * Implements *GeneralNames* ASN.1 type.
 *
 * Provides convenience methods to retrieve the first value of commonly used
 * CHOICE types.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class GeneralNames implements \Countable, \IteratorAggregate
{
    /**
     * GeneralName objects.
     *
     * @var GeneralName[]
     */
    protected $_names;

    /**
     * Constructor.
     *
     * @param GeneralName ...$names One or more GeneralName objects
     */
    public function __construct(GeneralName ...$names)
    {
        $this->_names = $names;
    }

    /**
     * Initialize from ASN.1.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromASN1(Sequence $seq): GeneralNames
    {
        if (!count($seq)) {
            throw new \UnexpectedValueException(
                'GeneralNames must have at least one GeneralName.');
        }
        $names = array_map(
            function (UnspecifiedType $el) {
                return GeneralName::fromASN1($el->asTagged());
            }, $seq->elements());
        return new self(...$names);
    }

    /**
     * Check whether GeneralNames contains a GeneralName of given type.
     *
     * @param int $tag One of `GeneralName::TAG_*` enumerations
     */
    public function has(int $tag): bool
    {
        return null !== $this->_findFirst($tag);
    }

    /**
     * Get first GeneralName of given type.
     *
     * @param int $tag One of `GeneralName::TAG_*` enumerations
     *
     * @throws \OutOfBoundsException
     */
    public function firstOf(int $tag): GeneralName
    {
        $name = $this->_findFirst($tag);
        if (!$name) {
            throw new \UnexpectedValueException("No GeneralName by tag {$tag}.");
        }
        return $name;
    }

    /**
     * Get all GeneralName objects of given type.
     *
     * @param int $tag One of `GeneralName::TAG_*` enumerations
     *
     * @return GeneralName[]
     */
    public function allOf(int $tag): array
    {
        $names = array_filter($this->_names,
            function (GeneralName $name) use ($tag) {
                return $name->tag() === $tag;
            });
        return array_values($names);
    }

    /**
     * Get value of the first 'dNSName' type.
     */
    public function firstDNS(): string
    {
        $gn = $this->firstOf(GeneralName::TAG_DNS_NAME);
        if (!$gn instanceof DNSName) {
            throw new \RuntimeException(
                DNSName::class . ' expected, got ' . get_class($gn));
        }
        return $gn->name();
    }

    /**
     * Get value of the first 'directoryName' type.
     */
    public function firstDN(): Name
    {
        $gn = $this->firstOf(GeneralName::TAG_DIRECTORY_NAME);
        if (!$gn instanceof DirectoryName) {
            throw new \RuntimeException(
                DirectoryName::class . ' expected, got ' . get_class($gn));
        }
        return $gn->dn();
    }

    /**
     * Get value of the first 'uniformResourceIdentifier' type.
     */
    public function firstURI(): string
    {
        $gn = $this->firstOf(GeneralName::TAG_URI);
        if (!$gn instanceof UniformResourceIdentifier) {
            throw new \RuntimeException(
                UniformResourceIdentifier::class . ' expected, got ' . get_class($gn));
        }
        return $gn->uri();
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        if (!count($this->_names)) {
            throw new \LogicException(
                'GeneralNames must have at least one GeneralName.');
        }
        $elements = array_map(
            function (GeneralName $name) {
                return $name->toASN1();
            }, $this->_names);
        return new Sequence(...$elements);
    }

    /**
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_names);
    }

    /**
     * Get iterator for GeneralName objects.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_names);
    }

    /**
     * Find first GeneralName by given tag.
     */
    protected function _findFirst(int $tag): ?GeneralName
    {
        foreach ($this->_names as $name) {
            if ($name->tag() === $tag) {
                return $name;
            }
        }
        return null;
    }
}
