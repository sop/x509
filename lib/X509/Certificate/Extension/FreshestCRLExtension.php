<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;

/**
 * Implements 'Freshest CRL' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.15
 */
class FreshestCRLExtension extends CRLDistributionPointsExtension
{
    /**
     * Constructor.
     *
     * @param bool              $critical
     * @param DistributionPoint ...$distribution_points
     */
    public function __construct(bool $critical,
        DistributionPoint ...$distribution_points)
    {
        Extension::__construct(self::OID_FRESHEST_CRL, $critical);
        $this->_distributionPoints = $distribution_points;
    }
}
