<?php

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;
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
class TargetInformationExtension extends Extension implements \Countable, 
	\IteratorAggregate
{
	/**
	 * Targets elements.
	 *
	 * @var Targets[] $_targets
	 */
	protected $_targets;
	
	/**
	 * Targets[] merged to Target[].
	 *
	 * @var Target[]|null
	 */
	private $_merged;
	
	/**
	 * Constructor
	 *
	 * @param bool $critical
	 * @param Targets ...$targets
	 */
	public function __construct($critical, Targets ...$targets) {
		parent::__construct(self::OID_TARGET_INFORMATION, $critical);
		$this->_targets = $targets;
	}
	
	protected static function _fromDER($data, $critical) {
		$targets = array_map(
			function (UnspecifiedType $el) {
				return Targets::fromASN1($el->asSequence());
			}, Sequence::fromDER($data)->elements());
		return new self($critical, ...$targets);
	}
	
	/**
	 * Get all targets.
	 *
	 * @return Target[]
	 */
	public function targets() {
		if (!isset($this->_merged)) {
			$a = array();
			foreach ($this->_targets as $targets) {
				$a = array_merge($a, $targets->all());
			}
			$this->_merged = $a;
		}
		return $this->_merged;
	}
	
	/**
	 * Get all name targets.
	 *
	 * @return Target[]
	 */
	public function names() {
		$targets = array_filter($this->targets(), 
			function (Target $target) {
				return $target->type() == Target::TYPE_NAME;
			});
		return array_values($targets);
	}
	
	/**
	 * Get all group targets.
	 *
	 * @return Target[]
	 */
	public function groups() {
		$targets = array_filter($this->targets(), 
			function (Target $target) {
				return $target->type() == Target::TYPE_GROUP;
			});
		return array_values($targets);
	}
	
	protected function _valueASN1() {
		$elements = array_map(
			function (Targets $targets) {
				return $targets->toASN1();
			}, $this->_targets);
		return new Sequence(...$elements);
	}
	
	public function count() {
		return count($this->targets());
	}
	
	/**
	 * Get iterator for targets.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->targets());
	}
}
