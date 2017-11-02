<?php

declare(strict_types=1);

namespace X509\AttributeCertificate\Attribute;

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use X501\ASN1\AttributeType;
use X501\ASN1\AttributeValue\AttributeValue;
use X501\MatchingRule\BinaryMatch;
use X509\GeneralName\GeneralName;
use X509\GeneralName\GeneralNames;
use X509\GeneralName\UniformResourceIdentifier;

/**
 * Implements value for 'Role' attribute.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.5
 */
class RoleAttributeValue extends AttributeValue
{
    /**
     * Issuing authority.
     *
     * @var GeneralNames $_roleAuthority
     */
    protected $_roleAuthority;
    
    /**
     * Role name.
     *
     * @var GeneralName $_roleName
     */
    protected $_roleName;
    
    /**
     * Constructor.
     *
     * @param GeneralName $name Role name
     * @param GeneralNames|null $authority Issuing authority
     */
    public function __construct(GeneralName $name, GeneralNames $authority = null)
    {
        $this->_roleAuthority = $authority;
        $this->_roleName = $name;
        $this->_oid = AttributeType::OID_ROLE;
    }
    
    /**
     * Initialize from a role string.
     *
     * @param string $role_name Role name in URI format
     * @param GeneralNames|null $authority Issuing authority
     * @return self
     */
    public static function fromString(string $role_name, GeneralNames $authority = null)
    {
        return new self(new UniformResourceIdentifier($role_name), $authority);
    }
    
    /**
     *
     * @param UnspecifiedType $el
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el)
    {
        $seq = $el->asSequence();
        $authority = null;
        if ($seq->hasTagged(0)) {
            $authority = GeneralNames::fromASN1(
                $seq->getTagged(0)
                    ->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        $name = GeneralName::fromASN1(
            $seq->getTagged(1)
                ->asExplicit()
                ->asTagged());
        return new self($name, $authority);
    }
    
    /**
     * Check whether issuing authority is present.
     *
     * @return bool
     */
    public function hasRoleAuthority(): bool
    {
        return isset($this->_roleAuthority);
    }
    
    /**
     * Get issuing authority.
     *
     * @throws \LogicException
     * @return GeneralNames
     */
    public function roleAuthority(): GeneralNames
    {
        if (!$this->hasRoleAuthority()) {
            throw new \LogicException("roleAuthority not set.");
        }
        return $this->_roleAuthority;
    }
    
    /**
     * Get role name.
     *
     * @return GeneralName
     */
    public function roleName(): GeneralName
    {
        return $this->_roleName;
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::toASN1()
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        $elements = array();
        if (isset($this->_roleAuthority)) {
            $elements[] = new ImplicitlyTaggedType(0,
                $this->_roleAuthority->toASN1());
        }
        $elements[] = new ExplicitlyTaggedType(1, $this->_roleName->toASN1());
        return new Sequence(...$elements);
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::stringValue()
     * @return string
     */
    public function stringValue(): string
    {
        return "#" . bin2hex($this->toASN1()->toDER());
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::equalityMatchingRule()
     * @return BinaryMatch
     */
    public function equalityMatchingRule(): BinaryMatch
    {
        return new BinaryMatch();
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::rfc2253String()
     * @return string
     */
    public function rfc2253String(): string
    {
        return $this->stringValue();
    }
    
    /**
     *
     * @see \X501\ASN1\AttributeValue\AttributeValue::_transcodedString()
     * @return string
     */
    protected function _transcodedString(): string
    {
        return $this->stringValue();
    }
}
