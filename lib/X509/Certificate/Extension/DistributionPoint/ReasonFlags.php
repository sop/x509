<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\DistributionPoint;

use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Util\Flags;

/**
 * Implements *ReasonFlags* ASN.1 type used by 'CRL Distribution Points'
 * certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class ReasonFlags
{
    // const UNUSED = 0x100;
    public const KEY_COMPROMISE = 0x080;
    public const CA_COMPROMISE = 0x040;
    public const AFFILIATION_CHANGED = 0x020;
    public const SUPERSEDED = 0x010;
    public const CESSATION_OF_OPERATION = 0x008;
    public const CERTIFICATE_HOLD = 0x004;
    public const PRIVILEGE_WITHDRAWN = 0x002;
    public const AA_COMPROMISE = 0x001;

    /**
     * Flags.
     *
     * @var int
     */
    protected $_flags;

    /**
     * Constructor.
     */
    public function __construct(int $flags)
    {
        $this->_flags = $flags;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(BitString $bs): self
    {
        return new self(Flags::fromBitString($bs, 9)->intNumber());
    }

    /**
     * Check whether keyCompromise flag is set.
     */
    public function isKeyCompromise(): bool
    {
        return $this->_flagSet(self::KEY_COMPROMISE);
    }

    /**
     * Check whether cACompromise flag is set.
     */
    public function isCACompromise(): bool
    {
        return $this->_flagSet(self::CA_COMPROMISE);
    }

    /**
     * Check whether affiliationChanged flag is set.
     */
    public function isAffiliationChanged(): bool
    {
        return $this->_flagSet(self::AFFILIATION_CHANGED);
    }

    /**
     * Check whether superseded flag is set.
     */
    public function isSuperseded(): bool
    {
        return $this->_flagSet(self::SUPERSEDED);
    }

    /**
     * Check whether cessationOfOperation flag is set.
     */
    public function isCessationOfOperation(): bool
    {
        return $this->_flagSet(self::CESSATION_OF_OPERATION);
    }

    /**
     * Check whether certificateHold flag is set.
     */
    public function isCertificateHold(): bool
    {
        return $this->_flagSet(self::CERTIFICATE_HOLD);
    }

    /**
     * Check whether privilegeWithdrawn flag is set.
     */
    public function isPrivilegeWithdrawn(): bool
    {
        return $this->_flagSet(self::PRIVILEGE_WITHDRAWN);
    }

    /**
     * Check whether aACompromise flag is set.
     */
    public function isAACompromise(): bool
    {
        return $this->_flagSet(self::AA_COMPROMISE);
    }

    /**
     * Generate ASN.1 element.
     */
    public function toASN1(): BitString
    {
        $flags = new Flags($this->_flags, 9);
        return $flags->bitString()->withoutTrailingZeroes();
    }

    /**
     * Check whether given flag is set.
     */
    protected function _flagSet(int $flag): bool
    {
        return (bool) ($this->_flags & $flag);
    }
}
