<?php

namespace X509\Certificate\Extension\Target;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;

/**
 * Implements <i>Targets</i> ASN.1 type as a <i>SEQUENCE OF Target</i>.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class Targets implements \Countable, \IteratorAggregate
{
    /**
     * Target elements.
     *
     * @var Target[] $_targets
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
     * @return self
     */
    public static function fromASN1(Sequence $seq)
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
    public function all()
    {
        return $this->_targets;
    }
    
    /**
     * Get all targets of given type.
     *
     * @param int $type
     * @return Target[]
     */
    protected function _allOfType($type)
    {
        return array_values(
            array_filter($this->_targets,
                function (Target $target) use ($type) {
                    return $target->type() == $type;
                }));
    }
    
    /**
     * Get all name targets.
     *
     * @return Target[]
     */
    public function nameTargets()
    {
        return $this->_allOfType(Target::TYPE_NAME);
    }
    
    /**
     * Get all group targets.
     *
     * @return Target[]
     */
    public function groupTargets()
    {
        return $this->_allOfType(Target::TYPE_GROUP);
    }
    
    /**
     * Check whether given target is present.
     *
     * @param Target $target
     * @return boolean
     */
    public function hasTarget(Target $target)
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
    public function toASN1()
    {
        $elements = array_map(
            function (Target $target) {
                return $target->toASN1();
            }, $this->_targets);
        return new Sequence(...$elements);
    }
    
    /**
     *
     * @see \Countable::count()
     * @return int
     */
    public function count()
    {
        return count($this->_targets);
    }
    
    /**
     * Get iterator for targets.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->_targets);
    }
}
