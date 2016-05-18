<?php

namespace X509\Certificate\Extension\Target;

use ASN1\Element;
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
	 * Constructor
	 *
	 * @param Target ...$targets
	 */
	public function __construct(Target ...$targets) {
		$this->_targets = $targets;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$targets = array_map(
			function (Element $el) {
				return Target::fromASN1($el->expectTagged());
			}, $seq->elements());
		return new self(...$targets);
	}
	
	/**
	 * Get all targets.
	 *
	 * @return Target[]
	 */
	public function all() {
		return $this->_targets;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array_map(
			function (Target $target) {
				return $target->toASN1();
			}, $this->_targets);
		return new Sequence(...$elements);
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_targets);
	}
	
	/**
	 * Get iterator for targets.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_targets);
	}
}
