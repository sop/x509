<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;

/**
 * Implements 'Certificate Policies' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class CertificatePoliciesExtension extends Extension implements \Countable, \IteratorAggregate
{
    /**
     * Policy information terms.
     *
     * @var PolicyInformation[]
     */
    protected $_policies;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, PolicyInformation ...$policies)
    {
        parent::__construct(Extension::OID_CERTIFICATE_POLICIES, $critical);
        $this->_policies = [];
        foreach ($policies as $policy) {
            $this->_policies[$policy->oid()] = $policy;
        }
    }

    /**
     * Check whether policy information by OID is present.
     */
    public function has(string $oid): bool
    {
        return isset($this->_policies[$oid]);
    }

    /**
     * Get policy information by OID.
     *
     * @throws \LogicException If not set
     */
    public function get(string $oid): PolicyInformation
    {
        if (!$this->has($oid)) {
            throw new \LogicException("Not certificate policy by OID {$oid}.");
        }
        return $this->_policies[$oid];
    }

    /**
     * Check whether anyPolicy is present.
     */
    public function hasAnyPolicy(): bool
    {
        return $this->has(PolicyInformation::OID_ANY_POLICY);
    }

    /**
     * Get anyPolicy information.
     *
     * @throws \LogicException if anyPolicy is not present
     */
    public function anyPolicy(): PolicyInformation
    {
        if (!$this->hasAnyPolicy()) {
            throw new \LogicException('No anyPolicy.');
        }
        return $this->get(PolicyInformation::OID_ANY_POLICY);
    }

    /**
     * Get the number of policies.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_policies);
    }

    /**
     * Get iterator for policy information terms.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_policies);
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $policies = array_map(
            function (UnspecifiedType $el) {
                return PolicyInformation::fromASN1($el->asSequence());
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        if (!count($policies)) {
            throw new \UnexpectedValueException(
                'certificatePolicies must contain at least one PolicyInformation.');
        }
        return new self($critical, ...$policies);
    }

    protected function _valueASN1(): Element
    {
        if (!count($this->_policies)) {
            throw new \LogicException('No policies.');
        }
        $elements = array_map(
            function (PolicyInformation $pi) {
                return $pi->toASN1();
            }, array_values($this->_policies));
        return new Sequence(...$elements);
    }
}
