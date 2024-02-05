<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Extended Key Usage' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.12
 */
class ExtendedKeyUsageExtension extends Extension implements \Countable, \IteratorAggregate
{
    public const OID_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
    public const OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
    public const OID_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
    public const OID_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';
    public const OID_IPSEC_END_SYSTEM = '1.3.6.1.5.5.7.3.5';
    public const OID_IPSEC_TUNNEL = '1.3.6.1.5.5.7.3.6';
    public const OID_IPSEC_USER = '1.3.6.1.5.5.7.3.7';
    public const OID_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
    public const OID_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
    public const OID_DVCS = '1.3.6.1.5.5.7.3.10';
    public const OID_SBGP_CERT_AA_SERVER_AUTH = '1.3.6.1.5.5.7.3.11';
    public const OID_SCVP_RESPONDER = '1.3.6.1.5.5.7.3.12';
    public const OID_EAP_OVER_PPP = '1.3.6.1.5.5.7.3.13';
    public const OID_EAP_OVER_LAN = '1.3.6.1.5.5.7.3.14';
    public const OID_SCVP_SERVER = '1.3.6.1.5.5.7.3.15';
    public const OID_SCVP_CLIENT = '1.3.6.1.5.5.7.3.16';
    public const OID_IPSEC_IKE = '1.3.6.1.5.5.7.3.17';
    public const OID_CAPWAP_AC = '1.3.6.1.5.5.7.3.18';
    public const OID_CAPWAP_WTP = '1.3.6.1.5.5.7.3.19';
    public const OID_SIP_DOMAIN = '1.3.6.1.5.5.7.3.20';
    public const OID_SECURE_SHELL_CLIENT = '1.3.6.1.5.5.7.3.21';
    public const OID_SECURE_SHELL_SERVER = '1.3.6.1.5.5.7.3.22';
    public const OID_SEND_ROUTER = '1.3.6.1.5.5.7.3.23';
    public const OID_SEND_PROXY = '1.3.6.1.5.5.7.3.24';
    public const OID_SEND_OWNER = '1.3.6.1.5.5.7.3.25';
    public const OID_SEND_PROXIED_OWNER = '1.3.6.1.5.5.7.3.26';
    public const OID_CMC_CA = '1.3.6.1.5.5.7.3.27';
    public const OID_CMC_RA = '1.3.6.1.5.5.7.3.28';
    public const OID_CMC_ARCHIVE = '1.3.6.1.5.5.7.3.29';
    public const OID_BIMI = '1.3.6.1.5.5.7.3.31';

    /**
     * Purpose OID's.
     *
     * @var string[]
     */
    protected $_purposes;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, string ...$purposes)
    {
        parent::__construct(self::OID_EXT_KEY_USAGE, $critical);
        $this->_purposes = $purposes;
    }

    /**
     * Whether purposes are present.
     *
     * If multiple purposes are checked, all must be present.
     */
    public function has(string ...$oids): bool
    {
        foreach ($oids as $oid) {
            if (!in_array($oid, $this->_purposes)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get key usage purpose OID's.
     *
     * @return string[]
     */
    public function purposes(): array
    {
        return $this->_purposes;
    }

    /**
     * Get the number of purposes.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_purposes);
    }

    /**
     * Get iterator for usage purposes.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_purposes);
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $purposes = array_map(
            function (UnspecifiedType $el) {
                return $el->asObjectIdentifier()->oid();
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        return new self($critical, ...$purposes);
    }

    protected function _valueASN1(): Element
    {
        $elements = array_map(
            function ($oid) {
                return new ObjectIdentifier($oid);
            }, $this->_purposes);
        return new Sequence(...$elements);
    }
}
