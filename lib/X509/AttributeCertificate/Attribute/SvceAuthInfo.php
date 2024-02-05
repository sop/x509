<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate\Attribute;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\BinaryMatch;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\GeneralName\GeneralName;

/**
 * Base class implementing *SvceAuthInfo* ASN.1 type used by
 * attribute certificate attribute values.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4.1
 */
abstract class SvceAuthInfo extends AttributeValue
{
    /**
     * Service.
     *
     * @var GeneralName
     */
    protected $_service;

    /**
     * Ident.
     *
     * @var GeneralName
     */
    protected $_ident;

    /**
     * Auth info.
     *
     * @var null|string
     */
    protected $_authInfo;

    /**
     * Constructor.
     */
    public function __construct(GeneralName $service, GeneralName $ident,
        ?string $auth_info = null)
    {
        $this->_service = $service;
        $this->_ident = $ident;
        $this->_authInfo = $auth_info;
    }

    /**
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        $seq = $el->asSequence();
        $service = GeneralName::fromASN1($seq->at(0)->asTagged());
        $ident = GeneralName::fromASN1($seq->at(1)->asTagged());
        $auth_info = null;
        if ($seq->has(2, Element::TYPE_OCTET_STRING)) {
            $auth_info = $seq->at(2)->asString()->string();
        }
        return new static($service, $ident, $auth_info);
    }

    /**
     * Get service name.
     */
    public function service(): GeneralName
    {
        return $this->_service;
    }

    /**
     * Get ident.
     */
    public function ident(): GeneralName
    {
        return $this->_ident;
    }

    /**
     * Check whether authentication info is present.
     */
    public function hasAuthInfo(): bool
    {
        return isset($this->_authInfo);
    }

    /**
     * Get authentication info.
     *
     * @throws \LogicException If not set
     */
    public function authInfo(): string
    {
        if (!$this->hasAuthInfo()) {
            throw new \LogicException('authInfo not set.');
        }
        return $this->_authInfo;
    }

    public function toASN1(): Element
    {
        $elements = [$this->_service->toASN1(), $this->_ident->toASN1()];
        if (isset($this->_authInfo)) {
            $elements[] = new OctetString($this->_authInfo);
        }
        return new Sequence(...$elements);
    }

    public function stringValue(): string
    {
        return '#' . bin2hex($this->toASN1()->toDER());
    }

    public function equalityMatchingRule(): MatchingRule
    {
        return new BinaryMatch();
    }

    public function rfc2253String(): string
    {
        return $this->stringValue();
    }

    protected function _transcodedString(): string
    {
        return $this->stringValue();
    }
}
