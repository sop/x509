<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;

/**
 * Implements 'Name Constraints' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
class NameConstraintsExtension extends Extension
{
    /**
     * Permitted subtrees.
     *
     * @var null|GeneralSubtrees
     */
    protected $_permitted;

    /**
     * Excluded subtrees.
     *
     * @var null|GeneralSubtrees
     */
    protected $_excluded;

    /**
     * Constructor.
     *
     * @param bool            $critical
     * @param GeneralSubtrees $permitted
     * @param GeneralSubtrees $excluded
     */
    public function __construct(bool $critical, ?GeneralSubtrees $permitted = null,
        ?GeneralSubtrees $excluded = null)
    {
        parent::__construct(self::OID_NAME_CONSTRAINTS, $critical);
        $this->_permitted = $permitted;
        $this->_excluded = $excluded;
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
     * @throws \LogicException If not set
     *
     * @return GeneralSubtrees
     */
    public function permittedSubtrees(): GeneralSubtrees
    {
        if (!$this->hasPermittedSubtrees()) {
            throw new \LogicException('No permitted subtrees.');
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
     * @throws \LogicException If not set
     *
     * @return GeneralSubtrees
     */
    public function excludedSubtrees(): GeneralSubtrees
    {
        if (!$this->hasExcludedSubtrees()) {
            throw new \LogicException('No excluded subtrees.');
        }
        return $this->_excluded;
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $permitted = null;
        $excluded = null;
        if ($seq->hasTagged(0)) {
            $permitted = GeneralSubtrees::fromASN1(
                $seq->getTagged(0)->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
        }
        if ($seq->hasTagged(1)) {
            $excluded = GeneralSubtrees::fromASN1(
                $seq->getTagged(1)->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
        }
        return new self($critical, $permitted, $excluded);
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        $elements = [];
        if (isset($this->_permitted)) {
            $elements[] = new ImplicitlyTaggedType(0, $this->_permitted->toASN1());
        }
        if (isset($this->_excluded)) {
            $elements[] = new ImplicitlyTaggedType(1, $this->_excluded->toASN1());
        }
        return new Sequence(...$elements);
    }
}
