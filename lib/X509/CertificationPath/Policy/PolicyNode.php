<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationPath\Policy;

use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Sop\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;

/**
 * Policy node class for certification path validation.
 *
 * @internal Mutable class used by PolicyTree
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.2
 */
class PolicyNode implements \IteratorAggregate, \Countable
{
    /**
     * Policy OID.
     *
     * @var string
     */
    protected $_validPolicy;

    /**
     * List of qualifiers.
     *
     * @var PolicyQualifierInfo[]
     */
    protected $_qualifiers;

    /**
     * List of expected policy OIDs.
     *
     * @var string[]
     */
    protected $_expectedPolicies;

    /**
     * List of child nodes.
     *
     * @var PolicyNode[]
     */
    protected $_children;

    /**
     * Reference to the parent node.
     *
     * @var null|PolicyNode
     */
    protected $_parent;

    /**
     * Constructor.
     *
     * @param string                $valid_policy      Policy OID
     * @param PolicyQualifierInfo[] $qualifiers
     * @param string[]              $expected_policies
     */
    public function __construct(string $valid_policy, array $qualifiers,
        array $expected_policies)
    {
        $this->_validPolicy = $valid_policy;
        $this->_qualifiers = $qualifiers;
        $this->_expectedPolicies = $expected_policies;
        $this->_children = [];
    }

    /**
     * Create initial node for the policy tree.
     *
     * @return self
     */
    public static function anyPolicyNode(): self
    {
        return new self(PolicyInformation::OID_ANY_POLICY, [],
            [PolicyInformation::OID_ANY_POLICY]);
    }

    /**
     * Get the valid policy OID.
     *
     * @return string
     */
    public function validPolicy(): string
    {
        return $this->_validPolicy;
    }

    /**
     * Check whether node has anyPolicy as a valid policy.
     *
     * @return bool
     */
    public function isAnyPolicy(): bool
    {
        return PolicyInformation::OID_ANY_POLICY === $this->_validPolicy;
    }

    /**
     * Get the qualifier set.
     *
     * @return PolicyQualifierInfo[]
     */
    public function qualifiers(): array
    {
        return $this->_qualifiers;
    }

    /**
     * Check whether node has OID as an expected policy.
     *
     * @param string $oid
     *
     * @return bool
     */
    public function hasExpectedPolicy(string $oid): bool
    {
        return in_array($oid, $this->_expectedPolicies);
    }

    /**
     * Get the expected policy set.
     *
     * @return string[]
     */
    public function expectedPolicies(): array
    {
        return $this->_expectedPolicies;
    }

    /**
     * Set expected policies.
     *
     * @param string ...$oids Policy OIDs
     */
    public function setExpectedPolicies(string ...$oids): void
    {
        $this->_expectedPolicies = $oids;
    }

    /**
     * Check whether node has a child node with given valid policy OID.
     *
     * @param string $oid
     *
     * @return bool
     */
    public function hasChildWithValidPolicy(string $oid): bool
    {
        foreach ($this->_children as $node) {
            if ($node->validPolicy() == $oid) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add child node.
     *
     * @param PolicyNode $node
     *
     * @return self
     */
    public function addChild(PolicyNode $node): self
    {
        $id = spl_object_hash($node);
        $node->_parent = $this;
        $this->_children[$id] = $node;
        return $this;
    }

    /**
     * Get the child nodes.
     *
     * @return PolicyNode[]
     */
    public function children(): array
    {
        return array_values($this->_children);
    }

    /**
     * Remove this node from the tree.
     *
     * @return self The removed node
     */
    public function remove(): self
    {
        if ($this->_parent) {
            $id = spl_object_hash($this);
            unset($this->_parent->_children[$id], $this->_parent);
        }
        return $this;
    }

    /**
     * Check whether node has a parent.
     *
     * @return bool
     */
    public function hasParent(): bool
    {
        return isset($this->_parent);
    }

    /**
     * Get the parent node.
     *
     * @return null|PolicyNode
     */
    public function parent(): ?PolicyNode
    {
        return $this->_parent;
    }

    /**
     * Get chain of parent nodes from this node's parent to the root node.
     *
     * @return PolicyNode[]
     */
    public function parents(): array
    {
        if (!$this->_parent) {
            return [];
        }
        $nodes = $this->_parent->parents();
        $nodes[] = $this->_parent;
        return array_reverse($nodes);
    }

    /**
     * Walk tree from this node, applying a callback for each node.
     *
     * Nodes are traversed depth-first and callback shall be applied post-order.
     *
     * @param callable $fn
     */
    public function walkNodes(callable $fn): void
    {
        foreach ($this->_children as $node) {
            $node->walkNodes($fn);
        }
        $fn($this);
    }

    /**
     * Get the total number of nodes in a tree.
     *
     * @return int
     */
    public function nodeCount(): int
    {
        $c = 1;
        foreach ($this->_children as $child) {
            $c += $child->nodeCount();
        }
        return $c;
    }

    /**
     * Get the number of child nodes.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_children);
    }

    /**
     * Get iterator for the child nodes.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_children);
    }
}
