<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\Certificate\Certificate;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements *Holder* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
class Holder
{
    /**
     * Holder PKC's issuer and serial.
     *
     * @var null|IssuerSerial
     */
    protected $_baseCertificateID;

    /**
     * Holder PKC's subject.
     *
     * @var null|GeneralNames
     */
    protected $_entityName;

    /**
     * Linked object.
     *
     * @var null|ObjectDigestInfo
     */
    protected $_objectDigestInfo;

    /**
     * Constructor.
     */
    public function __construct(?IssuerSerial $issuer_serial = null,
        ?GeneralNames $entity_name = null)
    {
        $this->_baseCertificateID = $issuer_serial;
        $this->_entityName = $entity_name;
    }

    /**
     * Initialize from a holder's public key certificate.
     */
    public static function fromPKC(Certificate $cert): self
    {
        return new self(IssuerSerial::fromPKC($cert));
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $cert_id = null;
        $entity_name = null;
        $digest_info = null;
        if ($seq->hasTagged(0)) {
            $cert_id = IssuerSerial::fromASN1(
                $seq->getTagged(0)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        if ($seq->hasTagged(1)) {
            $entity_name = GeneralNames::fromASN1(
                $seq->getTagged(1)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        if ($seq->hasTagged(2)) {
            $digest_info = ObjectDigestInfo::fromASN1(
                $seq->getTagged(2)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        $obj = new self($cert_id, $entity_name);
        $obj->_objectDigestInfo = $digest_info;
        return $obj;
    }

    /**
     * Get self with base certificate ID.
     */
    public function withBaseCertificateID(IssuerSerial $issuer): self
    {
        $obj = clone $this;
        $obj->_baseCertificateID = $issuer;
        return $obj;
    }

    /**
     * Get self with entity name.
     */
    public function withEntityName(GeneralNames $names): self
    {
        $obj = clone $this;
        $obj->_entityName = $names;
        return $obj;
    }

    /**
     * Get self with object digest info.
     */
    public function withObjectDigestInfo(ObjectDigestInfo $odi): self
    {
        $obj = clone $this;
        $obj->_objectDigestInfo = $odi;
        return $obj;
    }

    /**
     * Check whether base certificate ID is present.
     */
    public function hasBaseCertificateID(): bool
    {
        return isset($this->_baseCertificateID);
    }

    /**
     * Get base certificate ID.
     *
     * @throws \LogicException If not set
     */
    public function baseCertificateID(): IssuerSerial
    {
        if (!$this->hasBaseCertificateID()) {
            throw new \LogicException('baseCertificateID not set.');
        }
        return $this->_baseCertificateID;
    }

    /**
     * Check whether entity name is present.
     */
    public function hasEntityName(): bool
    {
        return isset($this->_entityName);
    }

    /**
     * Get entity name.
     *
     * @throws \LogicException If not set
     */
    public function entityName(): GeneralNames
    {
        if (!$this->hasEntityName()) {
            throw new \LogicException('entityName not set.');
        }
        return $this->_entityName;
    }

    /**
     * Check whether object digest info is present.
     */
    public function hasObjectDigestInfo(): bool
    {
        return isset($this->_objectDigestInfo);
    }

    /**
     * Get object digest info.
     *
     * @throws \LogicException If not set
     */
    public function objectDigestInfo(): ObjectDigestInfo
    {
        if (!$this->hasObjectDigestInfo()) {
            throw new \LogicException('objectDigestInfo not set.');
        }
        return $this->_objectDigestInfo;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [];
        if (isset($this->_baseCertificateID)) {
            $elements[] = new ImplicitlyTaggedType(0,
                $this->_baseCertificateID->toASN1());
        }
        if (isset($this->_entityName)) {
            $elements[] = new ImplicitlyTaggedType(1,
                $this->_entityName->toASN1());
        }
        if (isset($this->_objectDigestInfo)) {
            $elements[] = new ImplicitlyTaggedType(2,
                $this->_objectDigestInfo->toASN1());
        }
        return new Sequence(...$elements);
    }

    /**
     * Check whether Holder identifies given certificate.
     */
    public function identifiesPKC(Certificate $cert): bool
    {
        // if neither baseCertificateID nor entityName are present
        if (!$this->_baseCertificateID && !$this->_entityName) {
            return false;
        }
        // if baseCertificateID is present, but doesn't match
        if ($this->_baseCertificateID
            && !$this->_baseCertificateID->identifiesPKC($cert)) {
            return false;
        }
        // if entityName is present, but doesn't match
        if ($this->_entityName && !$this->_checkEntityName($cert)) {
            return false;
        }
        return true;
    }

    /**
     * Check whether entityName matches the given certificate.
     */
    private function _checkEntityName(Certificate $cert): bool
    {
        $name = $this->_entityName->firstDN();
        if ($cert->tbsCertificate()->subject()->equals($name)) {
            return true;
        }
        $exts = $cert->tbsCertificate()->extensions();
        if ($exts->hasSubjectAlternativeName()) {
            $ext = $exts->subjectAlternativeName();
            if ($this->_checkEntityAlternativeNames($ext->names())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether any of the subject alternative names match entityName.
     */
    private function _checkEntityAlternativeNames(GeneralNames $san): bool
    {
        // only directory names supported for now
        $name = $this->_entityName->firstDN();
        foreach ($san->allOf(GeneralName::TAG_DIRECTORY_NAME) as $dn) {
            if ($dn instanceof DirectoryName && $dn->dn()->equals($name)) {
                return true;
            }
        }
        return false;
    }
}
