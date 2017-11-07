<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * Implements 'Policy Constraints' certificate extensions.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.11
 */
class PolicyConstraintsExtension extends Extension
{
    /**
     *
     * @var int $_requireExplicitPolicy
     */
    protected $_requireExplicitPolicy;
    
    /**
     *
     * @var int $_inhibitPolicyMapping
     */
    protected $_inhibitPolicyMapping;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param int|null $require_explicit_policy
     * @param int|null $inhibit_policy_mapping
     */
    public function __construct(bool $critical, $require_explicit_policy = null,
        $inhibit_policy_mapping = null)
    {
        parent::__construct(self::OID_POLICY_CONSTRAINTS, $critical);
        $this->_requireExplicitPolicy = isset($require_explicit_policy) ? intval(
            $require_explicit_policy) : null;
        $this->_inhibitPolicyMapping = isset($inhibit_policy_mapping) ? intval(
            $inhibit_policy_mapping) : null;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER(string $data, bool $critical): self
    {
        $seq = Sequence::fromDER($data);
        $require_explicit_policy = null;
        $inhibit_policy_mapping = null;
        if ($seq->hasTagged(0)) {
            $require_explicit_policy = $seq->getTagged(0)
                ->asImplicit(Element::TYPE_INTEGER)
                ->asInteger()
                ->intNumber();
        }
        if ($seq->hasTagged(1)) {
            $inhibit_policy_mapping = $seq->getTagged(1)
                ->asImplicit(Element::TYPE_INTEGER)
                ->asInteger()
                ->intNumber();
        }
        return new self($critical, $require_explicit_policy,
            $inhibit_policy_mapping);
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
     * @throws \LogicException
     * @return int
     */
    public function requireExplicitPolicy(): int
    {
        if (!$this->hasRequireExplicitPolicy()) {
            throw new \LogicException("requireExplicitPolicy not set.");
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
     * @throws \LogicException
     * @return int
     */
    public function inhibitPolicyMapping(): int
    {
        if (!$this->hasInhibitPolicyMapping()) {
            throw new \LogicException("inhibitPolicyMapping not set.");
        }
        return $this->_inhibitPolicyMapping;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return Sequence
     */
    protected function _valueASN1(): Sequence
    {
        $elements = array();
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
