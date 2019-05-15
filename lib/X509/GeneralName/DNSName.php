<?php

declare(strict_types = 1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *dNSName* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class DNSName extends GeneralName
{
    /**
     * DNS name.
     *
     * @var string
     */
    protected $_name;

    /**
     * Constructor.
     *
     * @param string $name Domain name
     */
    public function __construct(string $name)
    {
        $this->_tag = self::TAG_DNS_NAME;
        $this->_name = $name;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        return new self($el->asIA5String()->string());
    }

    /**
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_name;
    }

    /**
     * Get DNS name.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->_name;
    }

    /**
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_name));
    }
}
