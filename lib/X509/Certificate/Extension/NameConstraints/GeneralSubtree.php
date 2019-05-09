<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\NameConstraints;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\GeneralName\GeneralName;

/**
 * Implements <i>GeneralSubtree</i> ASN.1 type used by
 * 'Name Constraints' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
class GeneralSubtree
{
    /**
     * Constraint.
     *
     * @var GeneralName
     */
    protected $_base;

    /**
     * Not used, must be zero.
     *
     * @var int
     */
    protected $_min;

    /**
     * Not used, must be null.
     *
     * @var null|int
     */
    protected $_max;

    /**
     * Constructor.
     *
     * @param GeneralName $base
     * @param int         $min
     * @param null|int    $max
     */
    public function __construct(GeneralName $base, int $min = 0, ?int $max = null)
    {
        $this->_base = $base;
        $this->_min = $min;
        $this->_max = $max;
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
        $base = GeneralName::fromASN1($seq->at(0)->asTagged());
        $min = 0;
        $max = null;
        if ($seq->hasTagged(0)) {
            $min = $seq->getTagged(0)->asImplicit(Element::TYPE_INTEGER)
                ->asInteger()->intNumber();
        }
        if ($seq->hasTagged(1)) {
            $max = $seq->getTagged(1)->asImplicit(Element::TYPE_INTEGER)
                ->asInteger()->intNumber();
        }
        return new self($base, $min, $max);
    }

    /**
     * Get constraint.
     *
     * @return GeneralName
     */
    public function base(): GeneralName
    {
        return $this->_base;
    }

    /**
     * Generate ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = [$this->_base->toASN1()];
        if (isset($this->_min) && 0 !== $this->_min) {
            $elements[] = new ImplicitlyTaggedType(0, new Integer($this->_min));
        }
        if (isset($this->_max)) {
            $elements[] = new ImplicitlyTaggedType(1, new Integer($this->_max));
        }
        return new Sequence(...$elements);
    }
}
