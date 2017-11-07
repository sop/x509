<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\Target\Target;
use X509\Certificate\Extension\Target\Targets;

/**
 * Implements 'AC Targeting' certificate extension.
 *
 * <b>NOTE</b>: Syntax is <i>SEQUENCE OF Targets</i>, but only one
 * <i>Targets</i> element must be used.
 * Multiple <i>Targets</i> elements shall be merged into single <i>Targets</i>.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class TargetInformationExtension extends Extension implements 
    \Countable,
    \IteratorAggregate
{
    /**
     * Targets elements.
     *
     * @var Targets[] $_targets
     */
    protected $_targets;
    
    /**
     * Targets[] merged to single Targets.
     *
     * @var Targets|null
     */
    private $_merged;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param Targets ...$targets
     */
    public function __construct(bool $critical, Targets ...$targets)
    {
        parent::__construct(self::OID_TARGET_INFORMATION, $critical);
        $this->_targets = $targets;
    }
    
    /**
     * Initialize from one or more Target objects.
     *
     * Extension criticality shall be set to true as specified by RFC 5755.
     *
     * @param Target ...$target
     * @return TargetInformationExtension
     */
    public static function fromTargets(Target ...$target): self
    {
        return new self(true, new Targets(...$target));
    }
    
    /**
     * Reset internal state on clone.
     */
    public function __clone()
    {
        $this->_merged = null;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER(string $data, bool $critical): self
    {
        $targets = array_map(
            function (UnspecifiedType $el) {
                return Targets::fromASN1($el->asSequence());
            }, Sequence::fromDER($data)->elements());
        return new self($critical, ...$targets);
    }
    
    /**
     * Get all targets.
     *
     * @return Targets
     */
    public function targets(): Targets
    {
        if (!isset($this->_merged)) {
            $a = array();
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
     *
     * @see \X509\Certificate\Extension\Extension::_valueASN1()
     * @return Sequence
     */
    protected function _valueASN1(): Sequence
    {
        $elements = array_map(
            function (Targets $targets) {
                return $targets->toASN1();
            }, $this->_targets);
        return new Sequence(...$elements);
    }
    
    /**
     *
     * @see \Countable::count()
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
     * @return \ArrayIterator
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->targets()->all());
    }
}
