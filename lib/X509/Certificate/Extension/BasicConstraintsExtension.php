<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Basic Constraints' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.9
 */
class BasicConstraintsExtension extends Extension
{
    /**
     * Whether certificate is a CA.
     *
     * @var bool
     */
    protected $_ca;

    /**
     * Maximum certification path length.
     *
     * @var null|int
     */
    protected $_pathLen;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, bool $ca, ?int $path_len = null)
    {
        parent::__construct(self::OID_BASIC_CONSTRAINTS, $critical);
        $this->_ca = $ca;
        $this->_pathLen = $path_len;
    }

    /**
     * Whether certificate is a CA.
     */
    public function isCA(): bool
    {
        return $this->_ca;
    }

    /**
     * Whether path length is present.
     */
    public function hasPathLen(): bool
    {
        return isset($this->_pathLen);
    }

    /**
     * Get path length.
     *
     * @throws \LogicException If not set
     */
    public function pathLen(): int
    {
        if (!$this->hasPathLen()) {
            throw new \LogicException('pathLenConstraint not set.');
        }
        return $this->_pathLen;
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $ca = false;
        $path_len = null;
        $idx = 0;
        if ($seq->has($idx, Element::TYPE_BOOLEAN)) {
            $ca = $seq->at($idx++)->asBoolean()->value();
        }
        if ($seq->has($idx, Element::TYPE_INTEGER)) {
            $path_len = $seq->at($idx)->asInteger()->intNumber();
        }
        return new self($critical, $ca, $path_len);
    }

    protected function _valueASN1(): Element
    {
        $elements = [];
        if ($this->_ca) {
            $elements[] = new Boolean(true);
        }
        if (isset($this->_pathLen)) {
            $elements[] = new Integer($this->_pathLen);
        }
        return new Sequence(...$elements);
    }
}
