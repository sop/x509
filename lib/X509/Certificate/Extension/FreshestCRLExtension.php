<?php

namespace X509\Certificate\Extension;

use X509\Certificate\Extension\DistributionPoint\DistributionPoint;


/**
 * Implements 'Freshest CRL' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.15
 */
class FreshestCRLExtension extends CRLDistributionPointsExtension
{
	/**
	 * Constructor
	 *
	 * @param bool $critical
	 * @param DistributionPoint ...$distribution_points
	 */
	public function __construct($critical, 
			DistributionPoint ...$distribution_points) {
		Extension::__construct(self::OID_FRESHEST_CRL, $critical);
		$this->_distributionPoints = $distribution_points;
	}
}
