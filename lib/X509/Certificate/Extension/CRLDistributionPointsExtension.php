<?php

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\DistributionPoint\DistributionPoint;


/**
 * Implements 'CRL Distribution Points' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class CRLDistributionPointsExtension extends Extension implements \Countable, 
	\IteratorAggregate
{
	/**
	 * Distribution points.
	 *
	 * @var DistributionPoint[] $_distributionPoints
	 */
	protected $_distributionPoints;
	
	/**
	 * Constructor
	 *
	 * @param bool $critical
	 * @param DistributionPoint ...$distribution_points
	 */
	public function __construct($critical, 
			DistributionPoint ...$distribution_points) {
		parent::__construct(self::OID_CRL_DISTRIBUTION_POINTS, $critical);
		$this->_distributionPoints = $distribution_points;
	}
	
	protected static function _fromDER($data, $critical) {
		$dps = array_map(
			function (Element $el) {
				return DistributionPoint::fromASN1(
					$el->expectType(Element::TYPE_SEQUENCE));
			}, Sequence::fromDER($data)->elements());
		if (!count($dps)) {
			throw new \UnexpectedValueException(
				"CRLDistributionPoints must have" .
					 " at least one DistributionPoint.");
		}
		// late static bound, extended by Freshest CRL extension
		return new static($critical, ...$dps);
	}
	
	protected function _valueASN1() {
		if (!count($this->_distributionPoints)) {
			throw new \LogicException("No distribution points.");
		}
		$elements = array_map(
			function (DistributionPoint $dp) {
				return $dp->toASN1();
			}, $this->_distributionPoints);
		return new Sequence(...$elements);
	}
	
	/**
	 * Get distribution points.
	 *
	 * @return DistributionPoint[]
	 */
	public function distributionPoints() {
		return $this->_distributionPoints;
	}
	
	/**
	 * Get the number of distribution points.
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_distributionPoints);
	}
	
	/**
	 * Get iterator for distribution points.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_distributionPoints);
	}
}
