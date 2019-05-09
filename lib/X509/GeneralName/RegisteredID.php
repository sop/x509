<?php

declare(strict_types = 1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements <i>registeredID</i> CHOICE type of <i>GeneralName</i>.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
class RegisteredID extends GeneralName
{
    /**
     * Object identifier.
     *
     * @var string
     */
    protected $_oid;

    /**
     * Constructor.
     *
     * @param string $oid OID in dotted format
     */
    public function __construct(string $oid)
    {
        $this->_tag = self::TAG_REGISTERED_ID;
        $this->_oid = $oid;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        return new self($el->asObjectIdentifier()->oid());
    }

    /**
     * {@inheritdoc}
     */
    public function string(): string
    {
        return $this->_oid;
    }

    /**
     * Get object identifier in dotted format.
     *
     * @return string OID
     */
    public function oid(): string
    {
        return $this->_oid;
    }

    /**
     * {@inheritdoc}
     */
    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag,
            new ObjectIdentifier($this->_oid));
    }
}
