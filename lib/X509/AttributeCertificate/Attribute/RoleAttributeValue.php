<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate\Attribute;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\BinaryMatch;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * Implements value for 'Role' attribute.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4.5
 */
class RoleAttributeValue extends AttributeValue
{
    /**
     * Issuing authority.
     *
     * @var null|GeneralNames
     */
    protected $_roleAuthority;

    /**
     * Role name.
     *
     * @var GeneralName
     */
    protected $_roleName;

    /**
     * Constructor.
     *
     * @param GeneralName       $name      Role name
     * @param null|GeneralNames $authority Issuing authority
     */
    public function __construct(GeneralName $name,
        ?GeneralNames $authority = null)
    {
        $this->_roleAuthority = $authority;
        $this->_roleName = $name;
        $this->_oid = AttributeType::OID_ROLE;
    }

    /**
     * Initialize from a role string.
     *
     * @param string            $role_name Role name in URI format
     * @param null|GeneralNames $authority Issuing authority
     *
     * @return self
     */
    public static function fromString(string $role_name,
        ?GeneralNames $authority = null): self
    {
        return new self(new UniformResourceIdentifier($role_name), $authority);
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        $seq = $el->asSequence();
        $authority = null;
        if ($seq->hasTagged(0)) {
            $authority = GeneralNames::fromASN1(
                $seq->getTagged(0)->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence());
        }
        $name = GeneralName::fromASN1($seq->getTagged(1)
            ->asExplicit()->asTagged());
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
     * @throws \LogicException If not set
     *
     * @return GeneralNames
     */
    public function roleAuthority(): GeneralNames
    {
        if (!$this->hasRoleAuthority()) {
            throw new \LogicException('roleAuthority not set.');
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
     * {@inheritdoc}
     */
    public function toASN1(): Element
    {
        $elements = [];
        if (isset($this->_roleAuthority)) {
            $elements[] = new ImplicitlyTaggedType(
                0, $this->_roleAuthority->toASN1());
        }
        $elements[] = new ExplicitlyTaggedType(
            1, $this->_roleName->toASN1());
        return new Sequence(...$elements);
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
