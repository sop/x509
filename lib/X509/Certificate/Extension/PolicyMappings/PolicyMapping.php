<?php

namespace X509\Certificate\Extension\PolicyMappings;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;

/**
 * Implements ASN.1 type containing policy mapping values to be used
 * in 'Policy Mappings' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.5
 */
class PolicyMapping
{
    /**
     * OID of the issuer policy.
     *
     * @var string $_issuerDomainPolicy
     */
    protected $_issuerDomainPolicy;
    
    /**
     * OID of the subject policy.
     *
     * @var string $_subjectDomainPolicy
     */
    protected $_subjectDomainPolicy;
    
    /**
     * Constructor.
     *
     * @param string $issuer_policy OID of the issuer policy
     * @param string $subject_policy OID of the subject policy
     */
    public function __construct($issuer_policy, $subject_policy)
    {
        $this->_issuerDomainPolicy = $issuer_policy;
        $this->_subjectDomainPolicy = $subject_policy;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $issuer_policy = $seq->at(0)
            ->asObjectIdentifier()
            ->oid();
        $subject_policy = $seq->at(1)
            ->asObjectIdentifier()
            ->oid();
        return new self($issuer_policy, $subject_policy);
    }
    
    /**
     * Get issuer domain policy.
     *
     * @return string OID in dotted format
     */
    public function issuerDomainPolicy()
    {
        return $this->_issuerDomainPolicy;
    }
    
    /**
     * Get subject domain policy.
     *
     * @return string OID in dotted format
     */
    public function subjectDomainPolicy()
    {
        return $this->_subjectDomainPolicy;
    }
    
    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1()
    {
        return new Sequence(new ObjectIdentifier($this->_issuerDomainPolicy),
            new ObjectIdentifier($this->_subjectDomainPolicy));
    }
}
