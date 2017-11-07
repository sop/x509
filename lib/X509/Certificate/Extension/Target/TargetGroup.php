<?php

declare(strict_types = 1);

namespace X509\Certificate\Extension\Target;

use ASN1\Type\TaggedType;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use X509\GeneralName\GeneralName;

/**
 * Implements 'targetGroup' CHOICE of the <i>Target</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class TargetGroup extends Target
{
    /**
     * Group name.
     *
     * @var GeneralName $_name
     */
    protected $_name;
    
    /**
     * Constructor.
     *
     * @param GeneralName $name
     */
    public function __construct(GeneralName $name)
    {
        $this->_name = $name;
        $this->_type = self::TYPE_GROUP;
    }
    
    /**
     *
     * @param TaggedType $el
     * @return self
     */
    public static function fromChosenASN1(TaggedType $el): self
    {
        return new self(GeneralName::fromASN1($el));
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_name->string();
    }
    
    /**
     * Get group name.
     *
     * @return GeneralName
     */
    public function name(): GeneralName
    {
        return $this->_name;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return ExplicitlyTaggedType
     */
    public function toASN1(): TaggedType
    {
        return new ExplicitlyTaggedType($this->_type, $this->_name->toASN1());
    }
}
