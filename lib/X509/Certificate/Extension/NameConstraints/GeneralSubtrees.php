<?php

namespace X509\Certificate\Extension\NameConstraints;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;


/**
 * Implements <i>GeneralSubtrees</i> ASN.1 type used by
 * 'Name Constraints' certificate extension.
 *
 * @link @link https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
class GeneralSubtrees implements \Countable, \IteratorAggregate
{
	/**
	 * Subtrees.
	 *
	 * @var GeneralSubtree[] $_subtrees
	 */
	protected $_subtrees;
	
	/**
	 * Constructor
	 *
	 * @param GeneralSubtree ...$subtrees
	 */
	public function __construct(GeneralSubtree ...$subtrees) {
		$this->_subtrees = $subtrees;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$subtrees = array_map(
			function (Element $el) {
				return GeneralSubtree::fromASN1(
					$el->expectType(Element::TYPE_SEQUENCE));
			}, $seq->elements());
		return new self(...$subtrees);
	}
	
	/**
	 * Get all subtrees.
	 *
	 * @return GeneralSubtree[]
	 */
	public function all() {
		return $this->_subtrees;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array_map(
			function (GeneralSubtree $gs) {
				return $gs->toASN1();
			}, $this->_subtrees);
		return new Sequence(...$elements);
	}
	
	/**
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_subtrees);
	}
	
	/**
	 * Get iterator for subtrees.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_subtrees);
	}
}
