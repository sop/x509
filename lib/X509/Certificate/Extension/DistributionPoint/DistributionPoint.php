<?php

namespace X509\Certificate\Extension\DistributionPoint;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\GeneralName\GeneralNames;

/**
 * Implements <i>DistributionPoint</i> ASN.1 type used by
 * 'CRL Distribution Points' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class DistributionPoint
{
    /**
     * Distribution point name.
     *
     * @var DistributionPointName $_distributionPoint
     */
    protected $_distributionPoint;
    
    /**
     * Revocation reason.
     *
     * @var ReasonFlags $_reasons
     */
    protected $_reasons;
    
    /**
     * CRL issuer.
     *
     * @var GeneralNames $_issuer
     */
    protected $_issuer;
    
    /**
     * Constructor.
     *
     * @param DistributionPointName $name
     * @param ReasonFlags $reasons
     * @param GeneralNames $issuer
     */
    public function __construct(DistributionPointName $name = null,
        ReasonFlags $reasons = null, GeneralNames $issuer = null)
    {
        $this->_distributionPoint = $name;
        $this->_reasons = $reasons;
        $this->_issuer = $issuer;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $name = null;
        $reasons = null;
        $issuer = null;
        if ($seq->hasTagged(0)) {
            // promoted to explicit tagging because underlying type is CHOICE
            $name = DistributionPointName::fromTaggedType(
                $seq->getTagged(0)
                    ->asExplicit()
                    ->asTagged());
        }
        if ($seq->hasTagged(1)) {
            $reasons = ReasonFlags::fromASN1(
                $seq->getTagged(1)
                    ->asImplicit(Element::TYPE_BIT_STRING)
                    ->asBitString());
        }
        if ($seq->hasTagged(2)) {
            $issuer = GeneralNames::fromASN1(
                $seq->getTagged(2)
                    ->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        return new self($name, $reasons, $issuer);
    }
    
    /**
     * Check whether distribution point name is set.
     *
     * @return bool
     */
    public function hasDistributionPointName()
    {
        return isset($this->_distributionPoint);
    }
    
    /**
     * Get distribution point name.
     *
     * @throws \LogicException
     * @return DistributionPointName
     */
    public function distributionPointName()
    {
        if (!$this->hasDistributionPointName()) {
            throw new \LogicException("distributionPoint not set.");
        }
        return $this->_distributionPoint;
    }
    
    /**
     * Check whether distribution point name is set and it's a full name.
     *
     * @return bool
     */
    public function hasFullName()
    {
        return $this->distributionPointName()->tag() ==
             DistributionPointName::TAG_FULL_NAME;
    }
    
    /**
     * Get full distribution point name.
     *
     * @throws \LogicException
     * @return FullName
     */
    public function fullName()
    {
        if (!$this->hasFullName()) {
            throw new \LogicException("fullName not set.");
        }
        return $this->_distributionPoint;
    }
    
    /**
     * Check whether distribution point name is set and it's a relative name.
     *
     * @return bool
     */
    public function hasRelativeName()
    {
        return $this->distributionPointName()->tag() ==
             DistributionPointName::TAG_RDN;
    }
    
    /**
     * Get relative distribution point name.
     *
     * @throws \LogicException
     * @return RelativeName
     */
    public function relativeName()
    {
        if (!$this->hasRelativeName()) {
            throw new \LogicException("nameRelativeToCRLIssuer not set.");
        }
        return $this->_distributionPoint;
    }
    
    /**
     * Check whether reasons flags is set.
     *
     * @return bool
     */
    public function hasReasons()
    {
        return isset($this->_reasons);
    }
    
    /**
     * Get revocation reason flags.
     *
     * @throws \LogicException
     * @return ReasonFlags
     */
    public function reasons()
    {
        if (!$this->hasReasons()) {
            throw new \LogicException("reasons not set.");
        }
        return $this->_reasons;
    }
    
    /**
     * Check whether cRLIssuer is set.
     *
     * @return bool
     */
    public function hasCRLIssuer()
    {
        return isset($this->_issuer);
    }
    
    /**
     * Get CRL issuer.
     *
     * @throws \LogicException
     * @return GeneralNames
     */
    public function crlIssuer()
    {
        if (!$this->hasCRLIssuer()) {
            throw new \LogicException("crlIssuer not set.");
        }
        return $this->_issuer;
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1()
    {
        $elements = array();
        if (isset($this->_distributionPoint)) {
            $elements[] = new ExplicitlyTaggedType(0,
                $this->_distributionPoint->toASN1());
        }
        if (isset($this->_reasons)) {
            $elements[] = new ImplicitlyTaggedType(1, $this->_reasons->toASN1());
        }
        if (isset($this->_issuer)) {
            $elements[] = new ImplicitlyTaggedType(2, $this->_issuer->toASN1());
        }
        return new Sequence(...$elements);
    }
}
