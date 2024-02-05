<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\CertificatePolicy;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Base class for *PolicyQualifierInfo* ASN.1 types used by 'Certificate Policies'
 * certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
abstract class PolicyQualifierInfo
{
    /**
     * OID for the CPS Pointer qualifier.
     *
     * @var string
     */
    public const OID_CPS = '1.3.6.1.5.5.7.2.1';

    /**
     * OID for the user notice qualifier.
     *
     * @var string
     */
    public const OID_UNOTICE = '1.3.6.1.5.5.7.2.2';

    /**
     * Qualifier identifier.
     *
     * @var string
     */
    protected $_oid;

    /**
     * Initialize from qualifier ASN.1 element.
     */
    public static function fromQualifierASN1(UnspecifiedType $el): PolicyQualifierInfo
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . ' must be implemented in the derived class.');
    }

    /**
     * Initialize from ASN.1.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromASN1(Sequence $seq): self
    {
        $oid = $seq->at(0)->asObjectIdentifier()->oid();
        switch ($oid) {
            case self::OID_CPS:
                return CPSQualifier::fromQualifierASN1($seq->at(1));
            case self::OID_UNOTICE:
                return UserNoticeQualifier::fromQualifierASN1($seq->at(1));
        }
        throw new \UnexpectedValueException("Qualifier {$oid} not supported.");
    }

    /**
     * Get qualifier identifier.
     */
    public function oid(): string
    {
        return $this->_oid;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return new Sequence(new ObjectIdentifier($this->_oid),
            $this->_qualifierASN1());
    }

    /**
     * Generate ASN.1 for the 'qualifier' field.
     */
    abstract protected function _qualifierASN1(): Element;
}
