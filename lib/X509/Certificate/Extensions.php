<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\CertificatePoliciesExtension;
use Sop\X509\Certificate\Extension\CRLDistributionPointsExtension;
use Sop\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use Sop\X509\Certificate\Extension\IssuerAlternativeNameExtension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extension\LogotypeExtension;
use Sop\X509\Certificate\Extension\NameConstraintsExtension;
use Sop\X509\Certificate\Extension\PolicyConstraintsExtension;
use Sop\X509\Certificate\Extension\PolicyMappingsExtension;
use Sop\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use Sop\X509\Certificate\Extension\SubjectKeyIdentifierExtension;

/**
 * Implements *Extensions* ASN.1 type.
 *
 * Several convenience methods are provided to fetch commonly used standard extensions.
 * Others can be accessed using `get($oid)`.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1.2.9
 */
class Extensions implements \Countable, \IteratorAggregate
{
    /**
     * Extensions.
     *
     * @var Extension[]
     */
    protected $_extensions;

    /**
     * Constructor.
     *
     * @param Extension ...$extensions Extension objects
     */
    public function __construct(Extension ...$extensions)
    {
        $this->_extensions = [];
        foreach ($extensions as $ext) {
            $this->_extensions[$ext->oid()] = $ext;
        }
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): Extensions
    {
        $extensions = array_map(
            function (UnspecifiedType $el) {
                return Extension::fromASN1($el->asSequence());
            }, $seq->elements());
        return new self(...$extensions);
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = array_values(
            array_map(
                function ($ext) {
                    return $ext->toASN1();
                }, $this->_extensions));
        return new Sequence(...$elements);
    }

    /**
     * Get self with extensions added.
     *
     * @param Extension ...$exts One or more extensions to add
     */
    public function withExtensions(Extension ...$exts): Extensions
    {
        $obj = clone $this;
        foreach ($exts as $ext) {
            $obj->_extensions[$ext->oid()] = $ext;
        }
        return $obj;
    }

    /**
     * Check whether extension is present.
     *
     * @param string $oid Extensions OID
     */
    public function has(string $oid): bool
    {
        return isset($this->_extensions[$oid]);
    }

    /**
     * Get extension by OID.
     *
     * @throws \LogicException If extension is not present
     */
    public function get(string $oid): Extension
    {
        if (!$this->has($oid)) {
            throw new \LogicException("No extension by OID {$oid}.");
        }
        return $this->_extensions[$oid];
    }

    /**
     * Check whether 'Authority Key Identifier' extension is present.
     */
    public function hasAuthorityKeyIdentifier(): bool
    {
        return $this->has(Extension::OID_AUTHORITY_KEY_IDENTIFIER);
    }

    /**
     * Get 'Authority Key Identifier' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function authorityKeyIdentifier(): AuthorityKeyIdentifierExtension
    {
        return $this->get(Extension::OID_AUTHORITY_KEY_IDENTIFIER);
    }

    /**
     * Check whether 'Subject Key Identifier' extension is present.
     */
    public function hasSubjectKeyIdentifier(): bool
    {
        return $this->has(Extension::OID_SUBJECT_KEY_IDENTIFIER);
    }

    /**
     * Get 'Subject Key Identifier' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function subjectKeyIdentifier(): SubjectKeyIdentifierExtension
    {
        return $this->get(Extension::OID_SUBJECT_KEY_IDENTIFIER);
    }

    /**
     * Check whether 'Key Usage' extension is present.
     */
    public function hasKeyUsage(): bool
    {
        return $this->has(Extension::OID_KEY_USAGE);
    }

    /**
     * Get 'Key Usage' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function keyUsage(): KeyUsageExtension
    {
        return $this->get(Extension::OID_KEY_USAGE);
    }

    /**
     * Check whether 'Certificate Policies' extension is present.
     */
    public function hasCertificatePolicies(): bool
    {
        return $this->has(Extension::OID_CERTIFICATE_POLICIES);
    }

    /**
     * Get 'Certificate Policies' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function certificatePolicies(): CertificatePoliciesExtension
    {
        return $this->get(Extension::OID_CERTIFICATE_POLICIES);
    }

    /**
     * Check whether 'Policy Mappings' extension is present.
     */
    public function hasPolicyMappings(): bool
    {
        return $this->has(Extension::OID_POLICY_MAPPINGS);
    }

    /**
     * Get 'Policy Mappings' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function policyMappings(): PolicyMappingsExtension
    {
        return $this->get(Extension::OID_POLICY_MAPPINGS);
    }

    /**
     * Check whether 'Subject Alternative Name' extension is present.
     */
    public function hasSubjectAlternativeName(): bool
    {
        return $this->has(Extension::OID_SUBJECT_ALT_NAME);
    }

    /**
     * Get 'Subject Alternative Name' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function subjectAlternativeName(): SubjectAlternativeNameExtension
    {
        return $this->get(Extension::OID_SUBJECT_ALT_NAME);
    }

    /**
     * Check whether 'Issuer Alternative Name' extension is present.
     */
    public function hasIssuerAlternativeName(): bool
    {
        return $this->has(Extension::OID_ISSUER_ALT_NAME);
    }

    /**
     * Get 'Issuer Alternative Name' extension.
     */
    public function issuerAlternativeName(): IssuerAlternativeNameExtension
    {
        return $this->get(Extension::OID_ISSUER_ALT_NAME);
    }

    /**
     * Check whether 'Basic Constraints' extension is present.
     */
    public function hasBasicConstraints(): bool
    {
        return $this->has(Extension::OID_BASIC_CONSTRAINTS);
    }

    /**
     * Get 'Basic Constraints' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function basicConstraints(): BasicConstraintsExtension
    {
        return $this->get(Extension::OID_BASIC_CONSTRAINTS);
    }

    /**
     * Check whether 'Name Constraints' extension is present.
     */
    public function hasNameConstraints(): bool
    {
        return $this->has(Extension::OID_NAME_CONSTRAINTS);
    }

    /**
     * Get 'Name Constraints' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function nameConstraints(): NameConstraintsExtension
    {
        return $this->get(Extension::OID_NAME_CONSTRAINTS);
    }

    /**
     * Check whether 'Policy Constraints' extension is present.
     */
    public function hasPolicyConstraints(): bool
    {
        return $this->has(Extension::OID_POLICY_CONSTRAINTS);
    }

    /**
     * Get 'Policy Constraints' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function policyConstraints(): PolicyConstraintsExtension
    {
        return $this->get(Extension::OID_POLICY_CONSTRAINTS);
    }

    /**
     * Check whether 'Extended Key Usage' extension is present.
     */
    public function hasExtendedKeyUsage(): bool
    {
        return $this->has(Extension::OID_EXT_KEY_USAGE);
    }

    /**
     * Get 'Extended Key Usage' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function extendedKeyUsage(): ExtendedKeyUsageExtension
    {
        return $this->get(Extension::OID_EXT_KEY_USAGE);
    }

    /**
     * Check whether 'CRL Distribution Points' extension is present.
     */
    public function hasCRLDistributionPoints(): bool
    {
        return $this->has(Extension::OID_CRL_DISTRIBUTION_POINTS);
    }

    /**
     * Get 'CRL Distribution Points' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function crlDistributionPoints(): CRLDistributionPointsExtension
    {
        return $this->get(Extension::OID_CRL_DISTRIBUTION_POINTS);
    }

    /**
     * Check whether 'Inhibit anyPolicy' extension is present.
     */
    public function hasInhibitAnyPolicy(): bool
    {
        return $this->has(Extension::OID_INHIBIT_ANY_POLICY);
    }

    /**
     * Get 'Inhibit anyPolicy' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function inhibitAnyPolicy(): InhibitAnyPolicyExtension
    {
        return $this->get(Extension::OID_INHIBIT_ANY_POLICY);
    }

    /**
     * Check whether 'Logotype' extension is present.
     */
    public function hasLogotype(): bool
    {
        return $this->has(Extension::OID_LOGOTYPE);
    }

    /**
     * Get 'Logotype' extension.
     *
     * @throws \LogicException If extension is not present
     */
    public function logotype(): LogotypeExtension
    {
        return $this->get(Extension::OID_LOGOTYPE);
    }

    /**
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_extensions);
    }

    /**
     * Get iterator for extensions.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->_extensions);
    }
}
