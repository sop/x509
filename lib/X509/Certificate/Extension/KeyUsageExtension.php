<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\ASN1\Util\Flags;

/**
 * Implements 'Key Usage' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.3
 */
class KeyUsageExtension extends Extension
{
    public const DIGITAL_SIGNATURE = 0x100;
    public const NON_REPUDIATION = 0x080;
    public const KEY_ENCIPHERMENT = 0x040;
    public const DATA_ENCIPHERMENT = 0x020;
    public const KEY_AGREEMENT = 0x010;
    public const KEY_CERT_SIGN = 0x008;
    public const CRL_SIGN = 0x004;
    public const ENCIPHER_ONLY = 0x002;
    public const DECIPHER_ONLY = 0x001;

    /**
     * Key usage flags.
     *
     * @var int
     */
    protected $_keyUsage;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, int $keyUsage)
    {
        parent::__construct(self::OID_KEY_USAGE, $critical);
        $this->_keyUsage = $keyUsage;
    }

    /**
     * Check whether digitalSignature flag is set.
     */
    public function isDigitalSignature(): bool
    {
        return $this->_flagSet(self::DIGITAL_SIGNATURE);
    }

    /**
     * Check whether nonRepudiation/contentCommitment flag is set.
     */
    public function isNonRepudiation(): bool
    {
        return $this->_flagSet(self::NON_REPUDIATION);
    }

    /**
     * Check whether keyEncipherment flag is set.
     */
    public function isKeyEncipherment(): bool
    {
        return $this->_flagSet(self::KEY_ENCIPHERMENT);
    }

    /**
     * Check whether dataEncipherment flag is set.
     */
    public function isDataEncipherment(): bool
    {
        return $this->_flagSet(self::DATA_ENCIPHERMENT);
    }

    /**
     * Check whether keyAgreement flag is set.
     */
    public function isKeyAgreement(): bool
    {
        return $this->_flagSet(self::KEY_AGREEMENT);
    }

    /**
     * Check whether keyCertSign flag is set.
     */
    public function isKeyCertSign(): bool
    {
        return $this->_flagSet(self::KEY_CERT_SIGN);
    }

    /**
     * Check whether cRLSign flag is set.
     */
    public function isCRLSign(): bool
    {
        return $this->_flagSet(self::CRL_SIGN);
    }

    /**
     * Check whether encipherOnly flag is set.
     */
    public function isEncipherOnly(): bool
    {
        return $this->_flagSet(self::ENCIPHER_ONLY);
    }

    /**
     * Check whether decipherOnly flag is set.
     */
    public function isDecipherOnly(): bool
    {
        return $this->_flagSet(self::DECIPHER_ONLY);
    }

    /**
     * Check whether given flag is set.
     */
    protected function _flagSet(int $flag): bool
    {
        return (bool) ($this->_keyUsage & $flag);
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        return new self($critical,
            Flags::fromBitString(
                UnspecifiedType::fromDER($data)->asBitString(), 9)->intNumber());
    }

    protected function _valueASN1(): Element
    {
        $flags = new Flags($this->_keyUsage, 9);
        return $flags->bitString()->withoutTrailingZeroes();
    }
}
