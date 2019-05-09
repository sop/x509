<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Policy Constraints' certificate extensions.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.11
 */
class PolicyConstraintsExtension extends Extension
{
    /**
     * @var null|int
     */
    protected $_requireExplicitPolicy;

    /**
     * @var null|int
     */
    protected $_inhibitPolicyMapping;

    /**
     * Constructor.
     *
     * @param bool     $critical
     * @param null|int $require_explicit_policy
     * @param null|int $inhibit_policy_mapping
     */
    public function __construct(bool $critical,
        ?int $require_explicit_policy = null, ?int $inhibit_policy_mapping = null)
    {
        parent::__construct(self::OID_POLICY_CONSTRAINTS, $critical);
        $this->_requireExplicitPolicy = $require_explicit_policy;
        $this->_inhibitPolicyMapping = $inhibit_policy_mapping;
    }

    /**
     * Whether requireExplicitPolicy is present.
     *
     * @return bool
     */
    public function hasRequireExplicitPolicy(): bool
    {
        return isset($this->_requireExplicitPolicy);
    }

    /**
     * Get requireExplicitPolicy.
     *
     * @throws \LogicException If not set
     *
     * @return int
     */
    public function requireExplicitPolicy(): int
    {
        if (!$this->hasRequireExplicitPolicy()) {
            throw new \LogicException('requireExplicitPolicy not set.');
        }
        return $this->_requireExplicitPolicy;
    }

    /**
     * Whether inhibitPolicyMapping is present.
     *
     * @return bool
     */
    public function hasInhibitPolicyMapping(): bool
    {
        return isset($this->_inhibitPolicyMapping);
    }

    /**
     * Get inhibitPolicyMapping.
     *
     * @throws \LogicException If not set
     *
     * @return int
     */
    public function inhibitPolicyMapping(): int
    {
        if (!$this->hasInhibitPolicyMapping()) {
            throw new \LogicException('inhibitPolicyMapping not set.');
        }
        return $this->_inhibitPolicyMapping;
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $require_explicit_policy = null;
        $inhibit_policy_mapping = null;
        if ($seq->hasTagged(0)) {
            $require_explicit_policy = $seq->getTagged(0)
                ->asImplicit(Element::TYPE_INTEGER)->asInteger()->intNumber();
        }
        if ($seq->hasTagged(1)) {
            $inhibit_policy_mapping = $seq->getTagged(1)
                ->asImplicit(Element::TYPE_INTEGER)->asInteger()->intNumber();
        }
        return new self($critical, $require_explicit_policy, $inhibit_policy_mapping);
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        $elements = [];
        if (isset($this->_requireExplicitPolicy)) {
            $elements[] = new ImplicitlyTaggedType(0,
                new Integer($this->_requireExplicitPolicy));
        }
        if (isset($this->_inhibitPolicyMapping)) {
            $elements[] = new ImplicitlyTaggedType(1,
                new Integer($this->_inhibitPolicyMapping));
        }
        return new Sequence(...$elements);
    }
}
