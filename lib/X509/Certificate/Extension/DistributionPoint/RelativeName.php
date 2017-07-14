<?php

namespace X509\Certificate\Extension\DistributionPoint;

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
    public function rdn()
    {
        return $this->_rdn;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return \ASN1\Type\Constructed\Set
     */
    protected function _valueASN1()
    {
        return $this->_rdn->toASN1();
    }
}
