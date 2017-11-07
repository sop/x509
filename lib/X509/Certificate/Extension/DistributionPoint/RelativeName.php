<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension\DistributionPoint;

use ASN1\Type\Constructed\Set;
use X501\ASN1\RDN;

/**
 * Implements 'nameRelativeToCRLIssuer' ASN.1 CHOICE type of
 * <i>DistributionPointName</i> used by 'CRL Distribution Points'
 * certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class RelativeName extends DistributionPointName
{
    /**
     * Relative distinguished name.
     *
     * @var RDN $_rdn
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
     *
     * {@inheritdoc}
     * @return Set
     */
    protected function _valueASN1(): Set
    {
        return $this->_rdn->toASN1();
    }
}
