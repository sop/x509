<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Target;

use Sop\ASN1\Element;
use Sop\ASN1\Type\TaggedType;

/**
 * Base class for *Target* ASN.1 CHOICE type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
abstract class Target
{
    public const TYPE_NAME = 0;
    public const TYPE_GROUP = 1;
    public const TYPE_CERT = 2;

    /**
     * Type tag.
     *
     * @var int
     */
    protected $_type;

    /**
     * Generate ASN.1 element.
     */
    abstract public function toASN1(): Element;

    /**
     * Get string value of the target.
     */
    abstract public function string(): string;

    /**
     * Initialize concrete object from the chosen ASN.1 element.
     */
    public static function fromChosenASN1(TaggedType $el): Target
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . ' must be implemented in the derived class.');
    }

    /**
     * Parse from ASN.1.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromASN1(TaggedType $el): self
    {
        switch ($el->tag()) {
            case self::TYPE_NAME:
                return TargetName::fromChosenASN1($el->asExplicit()->asTagged());
            case self::TYPE_GROUP:
                return TargetGroup::fromChosenASN1($el->asExplicit()->asTagged());
            case self::TYPE_CERT:
                throw new \RuntimeException('targetCert not supported.');
        }
        throw new \UnexpectedValueException(
            'Target type ' . $el->tag() . ' not supported.');
    }

    /**
     * Get type tag.
     */
    public function type(): int
    {
        return $this->_type;
    }

    /**
     * Check whether target is equal to another.
     */
    public function equals(Target $other): bool
    {
        if ($this->_type !== $other->_type) {
            return false;
        }
        if ($this->toASN1()->toDER() !== $other->toASN1()->toDER()) {
            return false;
        }
        return true;
    }
}
