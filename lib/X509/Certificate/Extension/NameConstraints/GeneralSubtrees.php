<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\NameConstraints;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements <i>GeneralSubtrees</i> ASN.1 type used by
 * 'Name Constraints' certificate extension.
 *
 * @see @link https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
class GeneralSubtrees implements \Countable, \IteratorAggregate
{
    /**
     * Subtrees.
     *
     * @var GeneralSubtree[]
     */
    protected $_subtrees;

    /**
     * Constructor.
     *
     * @param GeneralSubtree ...$subtrees
     */
    public function __construct(GeneralSubtree ...$subtrees)
    {
        $this->_subtrees = $subtrees;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $subtrees = array_map(
            function (UnspecifiedType $el) {
                return GeneralSubtree::fromASN1($el->asSequence());
            }, $seq->elements());
        if (!count($subtrees)) {
            throw new \UnexpectedValueException(
                'GeneralSubtrees must contain at least one GeneralSubtree.');
        }
        return new self(...$subtrees);
    }

    /**
     * Get all subtrees.
     *
     * @return GeneralSubtree[]
     */
    public function all(): array
    {
        return $this->_subtrees;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        if (!count($this->_subtrees)) {
            throw new \LogicException('No subtrees.');
        }
        $elements = array_map(
            function (GeneralSubtree $gs) {
                return $gs->toASN1();
            }, $this->_subtrees);
        return new Sequence(...$elements);
    }

    /**
     * @see \Countable::count()
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->_subtrees);
    }

    /**
     * Get iterator for subtrees.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_subtrees);
    }
}
