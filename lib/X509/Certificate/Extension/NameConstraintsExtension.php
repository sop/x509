<?php

declare(strict_types=1);

namespace X509\Certificate\Extension;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X509\Certificate\Extension\NameConstraints\GeneralSubtrees;

/**
 * Implements 'Name Constraints' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
class NameConstraintsExtension extends Extension
{
    /**
     * Permitted subtrees.
     *
     * @var GeneralSubtrees|null $_permitted
     */
    protected $_permitted;
    
    /**
     * Excluded subtrees.
     *
     * @var GeneralSubtrees|null $_excluded
     */
    protected $_excluded;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param GeneralSubtrees $permitted
     * @param GeneralSubtrees $excluded
     */
    public function __construct(bool $critical, GeneralSubtrees $permitted = null,
        GeneralSubtrees $excluded = null)
    {
        parent::__construct(self::OID_NAME_CONSTRAINTS, $critical);
        $this->_permitted = $permitted;
        $this->_excluded = $excluded;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER($data, $critical)
    {
        $seq = Sequence::fromDER($data);
        $permitted = null;
        $excluded = null;
        if ($seq->hasTagged(0)) {
            $permitted = GeneralSubtrees::fromASN1(
                $seq->getTagged(0)
                    ->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        if ($seq->hasTagged(1)) {
            $excluded = GeneralSubtrees::fromASN1(
                $seq->getTagged(1)
                    ->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        return new self($critical, $permitted, $excluded);
    }
    
    /**
     * Whether permitted subtrees are present.
     *
     * @return bool
     */
    public function hasPermittedSubtrees(): bool
    {
        return isset($this->_permitted);
    }
    
    /**
     * Get permitted subtrees.
     *
     * @throws \LogicException
     * @return GeneralSubtrees
     */
    public function permittedSubtrees(): GeneralSubtrees
    {
        if (!$this->hasPermittedSubtrees()) {
            throw new \LogicException("No permitted subtrees.");
        }
        return $this->_permitted;
    }
    
    /**
     * Whether excluded subtrees are present.
     *
     * @return bool
     */
    public function hasExcludedSubtrees(): bool
    {
        return isset($this->_excluded);
    }
    
    /**
     * Get excluded subtrees.
     *
     * @throws \LogicException
     * @return GeneralSubtrees
     */
    public function excludedSubtrees(): GeneralSubtrees
    {
        if (!$this->hasExcludedSubtrees()) {
            throw new \LogicException("No excluded subtrees.");
        }
        return $this->_excluded;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return Sequence
     */
    protected function _valueASN1()
    {
        $elements = array();
        if (isset($this->_permitted)) {
            $elements[] = new ImplicitlyTaggedType(0, $this->_permitted->toASN1());
        }
        if (isset($this->_excluded)) {
            $elements[] = new ImplicitlyTaggedType(1, $this->_excluded->toASN1());
        }
        return new Sequence(...$elements);
    }
}
