<?php

namespace X509\Certificate\Extension\Target;

use ASN1\Type\TaggedType;

/**
 * Base class for <i>Target</i> ASN.1 CHOICE type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
abstract class Target
{
    const TYPE_NAME = 0;
    const TYPE_GROUP = 1;
    const TYPE_CERT = 2;
    
    /**
     * Type tag.
     *
     * @var int $_type
     */
    protected $_type;
    
    /**
     * Generate ASN.1 element.
     *
     * @return \ASN1\Element
     */
    abstract public function toASN1();
    
    /**
     * Get string value of the target.
     *
     * @return string
     */
    abstract public function string();
    
    /**
     * Initialize concrete object from the chosen ASN.1 element.
     *
     * @param TaggedType $el
     * @return self
     */
    public static function fromChosenASN1(TaggedType $el)
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . " must be implemented in the derived class.");
    }
    
    /**
     * Parse from ASN.1.
     *
     * @param TaggedType $el
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromASN1(TaggedType $el)
    {
        switch ($el->tag()) {
            case self::TYPE_NAME:
                return TargetName::fromChosenASN1($el->asExplicit()->asTagged());
            case self::TYPE_GROUP:
                return TargetGroup::fromChosenASN1(
                    $el->asExplicit()->asTagged());
            case self::TYPE_CERT:
                throw new \RuntimeException("targetCert not supported.");
        }
        throw new \UnexpectedValueException(
            "Target type " . $el->tag() . " not supported.");
    }
    
    /**
     * Get type tag.
     *
     * @return int
     */
    public function type()
    {
        return $this->_type;
    }
    
    /**
     * Check whether target is equal to another.
     *
     * @param Target $other
     * @return bool
     */
    public function equals(Target $other)
    {
        if ($this->_type != $other->_type) {
            return false;
        }
        if ($this->toASN1()->toDER() != $other->toASN1()->toDER()) {
            return false;
        }
        return true;
    }
}
