<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\X509\GeneralName\GeneralNames;

/**
 * Implements 'Authority Key Identifier' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.1
 */
class AuthorityKeyIdentifierExtension extends Extension
{
    /**
     * Key identifier.
     *
     * @var null|string
     */
    protected $_keyIdentifier;

    /**
     * Issuer name.
     *
     * @var null|GeneralNames
     */
    protected $_authorityCertIssuer;

    /**
     * Issuer serial number as a base 10 integer.
     *
     * @var null|string
     */
    protected $_authorityCertSerialNumber;

    /**
     * Constructor.
     *
     * @param bool              $critical      Conforming CA's must mark as non-critical (false)
     * @param null|string       $keyIdentifier Key identifier
     * @param null|GeneralNames $issuer        Issuer name
     * @param null|int|string   $serial        Issuer serial number as a base 10 integer
     */
    public function __construct(bool $critical, ?string $keyIdentifier,
        ?GeneralNames $issuer = null, $serial = null)
    {
        parent::__construct(self::OID_AUTHORITY_KEY_IDENTIFIER, $critical);
        $this->_keyIdentifier = $keyIdentifier;
        $this->_authorityCertIssuer = $issuer;
        $this->_authorityCertSerialNumber = isset($serial) ? strval($serial) : null;
    }

    /**
     * Create from public key info.
     *
     * @param PublicKeyInfo $pki
     *
     * @return AuthorityKeyIdentifierExtension
     */
    public static function fromPublicKeyInfo(PublicKeyInfo $pki): self
    {
        return new self(false, $pki->keyIdentifier());
    }

    /**
     * Whether key identifier is present.
     *
     * @return bool
     */
    public function hasKeyIdentifier(): bool
    {
        return isset($this->_keyIdentifier);
    }

    /**
     * Get key identifier.
     *
     * @throws \LogicException If not set
     *
     * @return string
     */
    public function keyIdentifier(): string
    {
        if (!$this->hasKeyIdentifier()) {
            throw new \LogicException('keyIdentifier not set.');
        }
        return $this->_keyIdentifier;
    }

    /**
     * Whether issuer is present.
     *
     * @return bool
     */
    public function hasIssuer(): bool
    {
        return isset($this->_authorityCertIssuer);
    }

    /**
     * Get issuer.
     *
     * @throws \LogicException If not set
     *
     * @return GeneralNames
     */
    public function issuer(): GeneralNames
    {
        if (!$this->hasIssuer()) {
            throw new \LogicException('authorityCertIssuer not set.');
        }
        return $this->_authorityCertIssuer;
    }

    /**
     * Whether serial is present.
     *
     * @return bool
     */
    public function hasSerial(): bool
    {
        return isset($this->_authorityCertSerialNumber);
    }

    /**
     * Get serial number.
     *
     * @throws \LogicException If not set
     *
     * @return string Base 10 integer string
     */
    public function serial(): string
    {
        if (!$this->hasSerial()) {
            throw new \LogicException('authorityCertSerialNumber not set.');
        }
        return $this->_authorityCertSerialNumber;
    }

    /**
     * {@inheritdoc}
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $keyIdentifier = null;
        $issuer = null;
        $serial = null;
        if ($seq->hasTagged(0)) {
            $keyIdentifier = $seq->getTagged(0)
                ->asImplicit(Element::TYPE_OCTET_STRING)
                ->asOctetString()->string();
        }
        if ($seq->hasTagged(1) || $seq->hasTagged(2)) {
            if (!$seq->hasTagged(1) || !$seq->hasTagged(2)) {
                throw new \UnexpectedValueException(
                    'AuthorityKeyIdentifier must have both' .
                        ' authorityCertIssuer and authorityCertSerialNumber' .
                        ' present or both absent.');
            }
            $issuer = GeneralNames::fromASN1($seq->getTagged(1)
                ->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
            $serial = $seq->getTagged(2)->asImplicit(Element::TYPE_INTEGER)
                ->asInteger()->number();
        }
        return new self($critical, $keyIdentifier, $issuer, $serial);
    }

    /**
     * {@inheritdoc}
     */
    protected function _valueASN1(): Element
    {
        $elements = [];
        if (isset($this->_keyIdentifier)) {
            $elements[] = new ImplicitlyTaggedType(0,
                new OctetString($this->_keyIdentifier));
        }
        // if either issuer or serial is set, both must be set
        if (isset($this->_authorityCertIssuer) ||
             isset($this->_authorityCertSerialNumber)) {
            if (!isset($this->_authorityCertIssuer,
                $this->_authorityCertSerialNumber)) {
                throw new \LogicException(
                    'AuthorityKeyIdentifier must have both' .
                        ' authorityCertIssuer and authorityCertSerialNumber' .
                        ' present or both absent.');
            }
            $elements[] = new ImplicitlyTaggedType(1,
                $this->_authorityCertIssuer->toASN1());
            $elements[] = new ImplicitlyTaggedType(2,
                new Integer($this->_authorityCertSerialNumber));
        }
        return new Sequence(...$elements);
    }
}
