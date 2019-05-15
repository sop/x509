<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Target;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *Targets* ASN.1 type as a *SEQUENCE OF Target*.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class Targets implements \Countable, \IteratorAggregate
{
    /**
     * Target elements.
     *
     * @var Target[]
     */
    protected $_targets;

    /**
     * Constructor.
     *
     * @param Target ...$targets
     */
    public function __construct(Target ...$targets)
    {
        $this->_targets = $targets;
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
        $targets = array_map(
            function (UnspecifiedType $el) {
                return Target::fromASN1($el->asTagged());
            }, $seq->elements());
        return new self(...$targets);
    }

    /**
     * Get all targets.
     *
     * @return Target[]
     */
    public function all(): array
    {
        return $this->_targets;
    }

    /**
     * Get all name targets.
     *
     * @return Target[]
     */
    public function nameTargets(): array
    {
        return $this->_allOfType(Target::TYPE_NAME);
    }

    /**
     * Get all group targets.
     *
     * @return Target[]
     */
    public function groupTargets(): array
    {
        return $this->_allOfType(Target::TYPE_GROUP);
    }

    /**
     * Check whether given target is present.
     *
     * @param Target $target
     *
     * @return bool
     */
    public function hasTarget(Target $target): bool
    {
        foreach ($this->_allOfType($target->type()) as $t) {
            if ($target->equals($t)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array_map(
            function (Target $target) {
                return $target->toASN1();
            }, $this->_targets);
        return new Sequence(...$elements);
    }

    /**
     * @see \Countable::count()
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->_targets);
    }

    /**
     * Get iterator for targets.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_targets);
    }

    /**
     * Get all targets of given type.
     *
     * @param int $type
     *
     * @return Target[]
     */
    protected function _allOfType(int $type): array
    {
        return array_values(
            array_filter($this->_targets,
                function (Target $target) use ($type) {
                    return $target->type() === $type;
                }));
    }
}
