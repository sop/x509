<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\PolicyMappings;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;

/**
 * Implements ASN.1 type containing policy mapping values to be used
 * in 'Policy Mappings' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.5
 */
class PolicyMapping
{
    /**
     * OID of the issuer policy.
     *
     * @var string
     */
    protected $_issuerDomainPolicy;

    /**
     * OID of the subject policy.
     *
     * @var string
     */
    protected $_subjectDomainPolicy;

    /**
     * Constructor.
     *
     * @param string $issuer_policy  OID of the issuer policy
     * @param string $subject_policy OID of the subject policy
     */
    public function __construct(string $issuer_policy, string $subject_policy)
    {
        $this->_issuerDomainPolicy = $issuer_policy;
        $this->_subjectDomainPolicy = $subject_policy;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $issuer_policy = $seq->at(0)->asObjectIdentifier()->oid();
        $subject_policy = $seq->at(1)->asObjectIdentifier()->oid();
        return new self($issuer_policy, $subject_policy);
    }

    /**
     * Get issuer domain policy.
     *
     * @return string OID in dotted format
     */
    public function issuerDomainPolicy(): string
    {
        return $this->_issuerDomainPolicy;
    }

    /**
     * Get subject domain policy.
     *
     * @return string OID in dotted format
     */
    public function subjectDomainPolicy(): string
    {
        return $this->_subjectDomainPolicy;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        return new Sequence(new ObjectIdentifier($this->_issuerDomainPolicy),
            new ObjectIdentifier($this->_subjectDomainPolicy));
    }
}
