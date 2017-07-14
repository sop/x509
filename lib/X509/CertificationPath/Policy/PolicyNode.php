<?php

namespace X509\CertificationPath\Policy;

use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;

/**
 * Policy node class for certification path validation.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-6.1.2
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
     * @var \X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo[]
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
     * @var PolicyNode|null
     */
    protected $_parent;
    
    /**
     * Constructor.
     *
     * @param string $valid_policy Policy OID
     * @param \X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo[] $qualifiers
     * @param string[] $expected_policies
     */
    public function __construct($valid_policy, array $qualifiers,
        array $expected_policies)
    {
        $this->_validPolicy = $valid_policy;
        $this->_qualifiers = $qualifiers;
        $this->_expectedPolicies = $expected_policies;
        $this->_children = array();
    }
    
    /**
     * Create initial node for the policy tree.
     *
     * @return self
     */
    public static function anyPolicyNode()
    {
        return new self(PolicyInformation::OID_ANY_POLICY, array(),
            array(PolicyInformation::OID_ANY_POLICY));
    }
    
    /**
     * Get the valid policy OID.
     *
     * @return string
     */
    public function validPolicy()
    {
        return $this->_validPolicy;
    }
    
    /**
     * Check whether node has anyPolicy as a valid policy.
     *
     * @return boolean
     */
    public function isAnyPolicy()
    {
        return PolicyInformation::OID_ANY_POLICY == $this->_validPolicy;
    }
    
    /**
     * Get the qualifier set.
     *
     * @return \X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo[]
     */
    public function qualifiers()
    {
        return $this->_qualifiers;
    }
    
    /**
     * Check whether node has OID as an expected policy.
     *
     * @param string $oid
     * @return boolean
     */
    public function hasExpectedPolicy($oid)
    {
        return in_array($oid, $this->_expectedPolicies);
    }
    
    /**
     * Get the expected policy set.
     *
     * @return string[]
     */
    public function expectedPolicies()
    {
        return $this->_expectedPolicies;
    }
    
    /**
     * Set expected policies.
     *
     * @param string ...$oids Policy OIDs
     */
    public function setExpectedPolicies(...$oids)
    {
        $this->_expectedPolicies = $oids;
    }
    
    /**
     * Check whether node has a child node with given valid policy OID.
     *
     * @param string $oid
     * @return boolean
     */
    public function hasChildWithValidPolicy($oid)
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
     * @return self
     */
    public function addChild(PolicyNode $node)
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
    public function children()
    {
        return array_values($this->_children);
    }
    
    /**
     * Remove this node from the tree.
     *
     * @return self The removed node
     */
    public function remove()
    {
        if ($this->_parent) {
            $id = spl_object_hash($this);
            unset($this->_parent->_children[$id]);
            unset($this->_parent);
        }
        return $this;
    }
    
    /**
     * Check whether node has a parent.
     *
     * @return bool
     */
    public function hasParent()
    {
        return isset($this->_parent);
    }
    
    /**
     * Get the parent node.
     *
     * @return PolicyNode|null
     */
    public function parent()
    {
        return $this->_parent;
    }
    
    /**
     * Get chain of parent nodes from this node's parent to the root node.
     *
     * @return PolicyNode[]
     */
    public function parents()
    {
        if (!$this->_parent) {
            return array();
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
    public function walkNodes(callable $fn)
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
    public function nodeCount()
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
    public function count()
    {
        return count($this->_children);
    }
    
    /**
     * Get iterator for the child nodes.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->_children);
    }
}
