<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationRequest\Attribute;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\BinaryMatch;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\Certificate\Extensions;

/**
 * Implements value for 'Extension request' attribute.
 *
 * @see https://tools.ietf.org/html/rfc2985#page-17
 */
class ExtensionRequestValue extends AttributeValue
{
    const OID = '1.2.840.113549.1.9.14';

    /**
     * Extensions.
     *
     * @var Extensions
     */
    protected $_extensions;

    /**
     * Constructor.
     *
     * @param Extensions $extensions
     */
    public function __construct(Extensions $extensions)
    {
        $this->_extensions = $extensions;
        $this->_oid = self::OID;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        return new self(Extensions::fromASN1($el->asSequence()));
    }

    /**
     * Get requested extensions.
     *
     * @return Extensions
     */
    public function extensions(): Extensions
    {
        return $this->_extensions;
    }

    /**
     * {@inheritdoc}
     */
    public function toASN1(): Element
    {
        return $this->_extensions->toASN1();
    }

    /**
     * {@inheritdoc}
     */
    public function stringValue(): string
    {
        return '#' . bin2hex($this->toASN1()->toDER());
    }

    /**
     * {@inheritdoc}
     */
    public function equalityMatchingRule(): MatchingRule
    {
        return new BinaryMatch();
    }

    /**
     * {@inheritdoc}
     */
    public function rfc2253String(): string
    {
        return $this->stringValue();
    }

    /**
     * {@inheritdoc}
     */
    protected function _transcodedString(): string
    {
        return $this->stringValue();
    }
}
