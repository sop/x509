<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\DistributionPoint;

use Sop\ASN1\Element;
use Sop\X501\ASN1\RDN;

/**
 * Implements 'nameRelativeToCRLIssuer' ASN.1 CHOICE type of *DistributionPointName*
 * used by 'CRL Distribution Points' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class RelativeName extends DistributionPointName
{
    /**
     * Relative distinguished name.
     *
     * @var RDN
     */
    protected $_rdn;

    /**
     * Constructor.
     *
     * @param RDN $rdn
     */
    public function __construct(RDN $rdn)
    {
        $this->_tag = self::TAG_RDN;
        $this->_rdn = $rdn;
    }

    /**
     * Get RDN.
     *
     * @return RDN
     */
    public function rdn(): RDN
    {
        return $this->_rdn;
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        return $this->_rdn->toASN1();
    }
}
