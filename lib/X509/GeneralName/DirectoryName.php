<?php

declare(strict_types=1);

namespace X509\GeneralName;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use X501\ASN1\Name;

/**
 * Implements <i>directoryName</i> CHOICE type of <i>GeneralName</i>.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class DirectoryName extends GeneralName
{
    /**
     * Directory name.
     *
     * @var Name $_dn
     */
    protected $_dn;
    
    /**
     * Constructor.
     *
     * @param Name $dn
     */
    public function __construct(Name $dn)
    {
        $this->_tag = self::TAG_DIRECTORY_NAME;
        $this->_dn = $dn;
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el)
    {
        return new self(Name::fromASN1($el->asSequence()));
    }
    
    /**
     * Initialize from distinguished name string.
     *
     * @param string $str
     * @return self
     */
    public static function fromDNString($str)
    {
        return new self(Name::fromString($str));
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_dn->toString();
    }
    
    /**
     * Get directory name.
     *
     * @return Name
     */
    public function dn(): Name
    {
        return $this->_dn;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _choiceASN1()
    {
        // Name type is itself a CHOICE, so explicit tagging must be
        // employed to avoid ambiguities
        return new ExplicitlyTaggedType($this->_tag, $this->_dn->toASN1());
    }
}
