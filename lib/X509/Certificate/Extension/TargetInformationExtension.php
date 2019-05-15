<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\Targets;

/**
 * Implements 'AC Targeting' certificate extension.
 *
 * **NOTE**: Syntax is *SEQUENCE OF Targets*, but only one *Targets* element
 * must be used. Multiple *Targets* elements shall be merged into single *Targets*.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class TargetInformationExtension extends Extension implements \Countable, \IteratorAggregate
{
    /**
     * Targets elements.
     *
     * @var Targets[]
     */
    protected $_targets;

    /**
     * Targets[] merged to single Targets.
     *
     * @var null|Targets
     */
    private $_merged;

    /**
     * Constructor.
     *
     * @param bool    $critical
     * @param Targets ...$targets
     */
    public function __construct(bool $critical, Targets ...$targets)
    {
        parent::__construct(self::OID_TARGET_INFORMATION, $critical);
        $this->_targets = $targets;
    }

    /**
     * Reset internal state on clone.
     */
    public function __clone()
    {
        $this->_merged = null;
    }

    /**
     * Initialize from one or more Target objects.
     *
     * Extension criticality shall be set to true as specified by RFC 5755.
     *
     * @param Target ...$target
     *
     * @return TargetInformationExtension
     */
    public static function fromTargets(Target ...$target): self
    {
        return new self(true, new Targets(...$target));
    }

    /**
     * Get all targets.
     *
     * @return Targets
     */
    public function targets(): Targets
    {
        if (!isset($this->_merged)) {
            $a = [];
            foreach ($this->_targets as $targets) {
                $a = array_merge($a, $targets->all());
            }
            $this->_merged = new Targets(...$a);
        }
        return $this->_merged;
    }

    /**
     * Get all name targets.
     *
     * @return Target[]
     */
    public function names(): array
    {
        return $this->targets()->nameTargets();
    }

    /**
     * Get all group targets.
     *
     * @return Target[]
     */
    public function groups(): array
    {
        return $this->targets()->groupTargets();
    }

    /**
     * @see \Countable::count()
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->targets());
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
        return new \ArrayIterator($this->targets()->all());
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $targets = array_map(
            function (UnspecifiedType $el) {
                return Targets::fromASN1($el->asSequence());
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        return new self($critical, ...$targets);
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        $elements = array_map(
            function (Targets $targets) {
                return $targets->toASN1();
            }, $this->_targets);
        return new Sequence(...$elements);
    }
}
