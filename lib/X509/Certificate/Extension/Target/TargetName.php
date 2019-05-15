<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Target;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;

/**
 * Implements 'targetName' CHOICE of the *Target* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
class TargetName extends Target
{
    /**
     * Name.
     *
     * @var GeneralName
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
        $this->_type = self::TYPE_NAME;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromChosenASN1(TaggedType $el): Target
    {
        return new self(GeneralName::fromASN1($el));
    }

    /**
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_name->string();
    }

    /**
     * Get name.
     *
     * @return GeneralName
     */
    public function name(): GeneralName
    {
        return $this->_name;
    }

    /**
     * {@inheritdoc}
     */
    public function toASN1(): Element
    {
        return new ExplicitlyTaggedType($this->_type, $this->_name->toASN1());
    }
}
