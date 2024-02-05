<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\NameConstraints;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\GeneralName\GeneralName;

/**
 * Implements *GeneralSubtree* ASN.1 type used by 'Name Constraints'
 * certificate extension.
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
     */
    public function __construct(GeneralName $base, int $min = 0, ?int $max = null)
    {
        $this->_base = $base;
        $this->_min = $min;
        $this->_max = $max;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $base = GeneralName::fromASN1($seq->at(0)->asTagged());
        $min = 0;
        $max = null;
        // GeneralName is a CHOICE, which may be tagged as otherName [0]
        // or rfc822Name [1]. As minimum and maximum are also implicitly tagged,
        // we have to iterate the remaining elements instead of just checking
        // for tagged types.
        for ($i = 1; $i < count($seq); ++$i) {
            $el = $seq->at($i)->expectTagged();
            switch ($el->tag()) {
                case 0:
                    $min = $el->asImplicit(Element::TYPE_INTEGER)
                        ->asInteger()->intNumber();
                    break;
                case 1:
                    $max = $el->asImplicit(Element::TYPE_INTEGER)
                        ->asInteger()->intNumber();
                    break;
            }
        }
        return new self($base, $min, $max);
    }

    /**
     * Get constraint.
     */
    public function base(): GeneralName
    {
        return $this->_base;
    }

    /**
     * Generate ASN.1 structure.
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
