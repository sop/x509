<?php

declare(strict_types = 1);

namespace X509\GeneralName;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\IA5String;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\TaggedType;

/**
 * Implements <i>uniformResourceIdentifier</i> CHOICE type of
 * <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class UniformResourceIdentifier extends GeneralName
{
    /**
     * URI.
     *
     * @var string $_uri
     */
    protected $_uri;
    
    /**
     * Constructor.
     *
     * @param string $uri
     */
    public function __construct(string $uri)
    {
        $this->_tag = self::TAG_URI;
        $this->_uri = $uri;
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): self
    {
        return new self($el->asIA5String()->string());
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_uri;
    }
    
    /**
     * Get URI.
     *
     * @return string
     */
    public function uri(): string
    {
        return $this->_uri;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_uri));
    }
}
