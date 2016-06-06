<?php

namespace X509\Certificate\Extension\NameConstraints;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\GeneralName;


/**
 * Implements <i>GeneralSubtree</i> ASN.1 type used by
 * 'Name Constraints' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
class GeneralSubtree
{
	/**
	 * Constraint.
	 *
	 * @var GeneralName
	 */
	protected $_base;
	
	/**
	 * Not used, must be zero.
	 *
	 * @var int $_min
	 */
	protected $_min;
	
	/**
	 * Not used, must be null.
	 *
	 * @var int|null $_max
	 */
	protected $_max;
	
	/**
	 * Constructor
	 *
	 * @param GeneralName $base
	 * @param int $min
	 * @param int|null $max
	 */
	public function __construct(GeneralName $base, $min = 0, $max = null) {
		$this->_base = $base;
		$this->_min = $min;
		$this->_max = $max;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$base = GeneralName::fromASN1($seq->at(0)->asTagged());
		$min = 0;
		$max = null;
		if ($seq->hasTagged(0)) {
			$min = $seq->getTagged(0)
				->asImplicit(Element::TYPE_INTEGER)
				->asInteger()
				->number();
		}
		if ($seq->hasTagged(1)) {
			$max = $seq->getTagged(1)
				->asImplicit(Element::TYPE_INTEGER)
				->asInteger()
				->number();
		}
		return new self($base, $min, $max);
	}
	
	/**
	 * Get constraint.
	 *
	 * @return GeneralName
	 */
	public function base() {
		return $this->_base;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$elements = array($this->_base->toASN1());
		if (isset($this->_min) && $this->_min != 0) {
			$elements[] = new ImplicitlyTaggedType(0, new Integer($this->_min));
		}
		if (isset($this->_max)) {
			$elements[] = new ImplicitlyTaggedType(1, new Integer($this->_max));
		}
		return new Sequence(...$elements);
	}
}
