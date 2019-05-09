<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements <i>V2Form</i> ASN.1 type used as a attribute certificate issuer.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
class V2Form extends AttCertIssuer
{
    /**
     * Issuer name.
     *
     * @var null|GeneralNames
     */
    protected $_issuerName;

    /**
     * Issuer PKC's issuer and serial.
     *
     * @var IssuerSerial
     */
    protected $_baseCertificateID;

    /**
     * Linked object.
     *
     * @var ObjectDigestInfo
     */
    protected $_objectDigestInfo;

    /**
     * Constructor.
     *
     * @param null|GeneralNames $names
     */
    public function __construct(?GeneralNames $names = null)
    {
        $this->_issuerName = $names;
        $this->_baseCertificateID = null;
        $this->_objectDigestInfo = null;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @return self
     */
    public static function fromV2ASN1(Sequence $seq): self
    {
        $issuer = null;
        $cert_id = null;
        $digest_info = null;
        if ($seq->has(0, Element::TYPE_SEQUENCE)) {
            $issuer = GeneralNames::fromASN1($seq->at(0)->asSequence());
        }
        if ($seq->hasTagged(0)) {
            $cert_id = IssuerSerial::fromASN1(
                $seq->getTagged(0)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        if ($seq->hasTagged(1)) {
            $digest_info = ObjectDigestInfo::fromASN1(
                $seq->getTagged(1)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        $obj = new self($issuer);
        $obj->_baseCertificateID = $cert_id;
        $obj->_objectDigestInfo = $digest_info;
        return $obj;
    }

    /**
     * Check whether issuer name is set.
     *
     * @return bool
     */
    public function hasIssuerName(): bool
    {
        return isset($this->_issuerName);
    }

    /**
     * Get issuer name.
     *
     * @throws \LogicException If not set
     *
     * @return GeneralNames
     */
    public function issuerName(): GeneralNames
    {
        if (!$this->hasIssuerName()) {
            throw new \LogicException('issuerName not set.');
        }
        return $this->_issuerName;
    }

    /**
     * Get DN of the issuer.
     *
     * This is a convenience method conforming to RFC 5755, which states
     * that Issuer must contain only one non-empty distinguished name.
     *
     * @return Name
     */
    public function name(): Name
    {
        return $this->issuerName()->firstDN();
    }

    /**
     * {@inheritdoc}
     */
    public function toASN1(): Element
    {
        $elements = [];
        if (isset($this->_issuerName)) {
            $elements[] = $this->_issuerName->toASN1();
        }
        if (isset($this->_baseCertificateID)) {
            $elements[] = new ImplicitlyTaggedType(0,
                $this->_baseCertificateID->toASN1());
        }
        if (isset($this->_objectDigestInfo)) {
            $elements[] = new ImplicitlyTaggedType(1,
                $this->_objectDigestInfo->toASN1());
        }
        return new ImplicitlyTaggedType(0, new Sequence(...$elements));
    }

    /**
     * {@inheritdoc}
     */
    public function identifiesPKC(Certificate $cert): bool
    {
        $name = $this->_issuerName->firstDN();
        if (!$cert->tbsCertificate()->subject()->equals($name)) {
            return false;
        }
        return true;
    }
}
