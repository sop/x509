<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\UniqueIdentifier;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements *IssuerSerial* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 */
class IssuerSerial
{
    /**
     * Issuer name.
     *
     * @var GeneralNames
     */
    protected $_issuer;

    /**
     * Serial number as a base 10 integer.
     *
     * @var string
     */
    protected $_serial;

    /**
     * Issuer unique ID.
     *
     * @var null|UniqueIdentifier
     */
    protected $_issuerUID;

    /**
     * Constructor.
     *
     * @param GeneralNames          $issuer
     * @param int|string            $serial
     * @param null|UniqueIdentifier $uid
     */
    public function __construct(GeneralNames $issuer, $serial,
        ?UniqueIdentifier $uid = null)
    {
        $this->_issuer = $issuer;
        $this->_serial = strval($serial);
        $this->_issuerUID = $uid;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @return self
     */
    public static function fromASN1(Sequence $seq): IssuerSerial
    {
        $issuer = GeneralNames::fromASN1($seq->at(0)->asSequence());
        $serial = $seq->at(1)->asInteger()->number();
        $uid = null;
        if ($seq->has(2, Element::TYPE_BIT_STRING)) {
            $uid = UniqueIdentifier::fromASN1($seq->at(2)->asBitString());
        }
        return new self($issuer, $serial, $uid);
    }

    /**
     * Initialize from a public key certificate.
     *
     * @param Certificate $cert
     *
     * @return self
     */
    public static function fromPKC(Certificate $cert): IssuerSerial
    {
        $tbsCert = $cert->tbsCertificate();
        $issuer = new GeneralNames(new DirectoryName($tbsCert->issuer()));
        $serial = $tbsCert->serialNumber();
        $uid = $tbsCert->hasIssuerUniqueID() ? $tbsCert->issuerUniqueID() : null;
        return new self($issuer, $serial, $uid);
    }

    /**
     * Get issuer name.
     *
     * @return GeneralNames
     */
    public function issuer(): GeneralNames
    {
        return $this->_issuer;
    }

    /**
     * Get serial number.
     *
     * @return string
     */
    public function serial(): string
    {
        return $this->_serial;
    }

    /**
     * Check whether issuer unique identifier is present.
     *
     * @return bool
     */
    public function hasIssuerUID(): bool
    {
        return isset($this->_issuerUID);
    }

    /**
     * Get issuer unique identifier.
     *
     * @throws \LogicException If not set
     *
     * @return UniqueIdentifier
     */
    public function issuerUID(): UniqueIdentifier
    {
        if (!$this->hasIssuerUID()) {
            throw new \LogicException('issuerUID not set.');
        }
        return $this->_issuerUID;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = [$this->_issuer->toASN1(), new Integer($this->_serial)];
        if (isset($this->_issuerUID)) {
            $elements[] = $this->_issuerUID->toASN1();
        }
        return new Sequence(...$elements);
    }

    /**
     * Check whether this IssuerSerial identifies given certificate.
     *
     * @param Certificate $cert
     *
     * @return bool
     */
    public function identifiesPKC(Certificate $cert): bool
    {
        $tbs = $cert->tbsCertificate();
        if (!$tbs->issuer()->equals($this->_issuer->firstDN())) {
            return false;
        }
        if ($tbs->serialNumber() !== $this->_serial) {
            return false;
        }
        if ($this->_issuerUID && !$this->_checkUniqueID($cert)) {
            return false;
        }
        return true;
    }

    /**
     * Check whether issuerUID matches given certificate.
     *
     * @param Certificate $cert
     *
     * @return bool
     */
    private function _checkUniqueID(Certificate $cert): bool
    {
        if (!$cert->tbsCertificate()->hasIssuerUniqueID()) {
            return false;
        }
        $uid = $cert->tbsCertificate()->issuerUniqueID()->string();
        if ($this->_issuerUID->string() !== $uid) {
            return false;
        }
        return true;
    }
}
