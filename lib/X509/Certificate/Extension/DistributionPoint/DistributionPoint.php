<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\DistributionPoint;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements *DistributionPoint* ASN.1 type used by 'CRL Distribution Points'
 * certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class DistributionPoint
{
    /**
     * Distribution point name.
     *
     * @var null|DistributionPointName
     */
    protected $_distributionPoint;

    /**
     * Revocation reason.
     *
     * @var null|ReasonFlags
     */
    protected $_reasons;

    /**
     * CRL issuer.
     *
     * @var null|GeneralNames
     */
    protected $_issuer;

    /**
     * Constructor.
     */
    public function __construct(?DistributionPointName $name = null,
        ?ReasonFlags $reasons = null, ?GeneralNames $issuer = null)
    {
        $this->_distributionPoint = $name;
        $this->_reasons = $reasons;
        $this->_issuer = $issuer;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $name = null;
        $reasons = null;
        $issuer = null;
        if ($seq->hasTagged(0)) {
            // promoted to explicit tagging because underlying type is CHOICE
            $name = DistributionPointName::fromTaggedType(
                $seq->getTagged(0)->asExplicit()->asTagged());
        }
        if ($seq->hasTagged(1)) {
            $reasons = ReasonFlags::fromASN1(
                $seq->getTagged(1)->asImplicit(Element::TYPE_BIT_STRING)
                    ->asBitString());
        }
        if ($seq->hasTagged(2)) {
            $issuer = GeneralNames::fromASN1(
                $seq->getTagged(2)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        return new self($name, $reasons, $issuer);
    }

    /**
     * Check whether distribution point name is set.
     */
    public function hasDistributionPointName(): bool
    {
        return isset($this->_distributionPoint);
    }

    /**
     * Get distribution point name.
     *
     * @throws \LogicException If not set
     */
    public function distributionPointName(): DistributionPointName
    {
        if (!$this->hasDistributionPointName()) {
            throw new \LogicException('distributionPoint not set.');
        }
        return $this->_distributionPoint;
    }

    /**
     * Check whether distribution point name is set and it's a full name.
     */
    public function hasFullName(): bool
    {
        return DistributionPointName::TAG_FULL_NAME ===
             $this->distributionPointName()->tag();
    }

    /**
     * Get full distribution point name.
     *
     * @throws \LogicException If not set
     */
    public function fullName(): FullName
    {
        if (!$this->hasFullName()) {
            throw new \LogicException('fullName not set.');
        }
        return $this->_distributionPoint;
    }

    /**
     * Check whether distribution point name is set and it's a relative name.
     */
    public function hasRelativeName(): bool
    {
        return DistributionPointName::TAG_RDN ===
             $this->distributionPointName()->tag();
    }

    /**
     * Get relative distribution point name.
     *
     * @throws \LogicException If not set
     */
    public function relativeName(): RelativeName
    {
        if (!$this->hasRelativeName()) {
            throw new \LogicException('nameRelativeToCRLIssuer not set.');
        }
        return $this->_distributionPoint;
    }

    /**
     * Check whether reasons flags is set.
     */
    public function hasReasons(): bool
    {
        return isset($this->_reasons);
    }

    /**
     * Get revocation reason flags.
     *
     * @throws \LogicException If not set
     */
    public function reasons(): ReasonFlags
    {
        if (!$this->hasReasons()) {
            throw new \LogicException('reasons not set.');
        }
        return $this->_reasons;
    }

    /**
     * Check whether cRLIssuer is set.
     */
    public function hasCRLIssuer(): bool
    {
        return isset($this->_issuer);
    }

    /**
     * Get CRL issuer.
     *
     * @throws \LogicException If not set
     */
    public function crlIssuer(): GeneralNames
    {
        if (!$this->hasCRLIssuer()) {
            throw new \LogicException('crlIssuer not set.');
        }
        return $this->_issuer;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [];
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
