<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Inhibit anyPolicy' extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.14
 */
class InhibitAnyPolicyExtension extends Extension
{
    /**
     * @var int
     */
    protected $_skipCerts;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, int $skip_certs)
    {
        parent::__construct(self::OID_INHIBIT_ANY_POLICY, $critical);
        $this->_skipCerts = $skip_certs;
    }

    /**
     * Get value.
     */
    public function skipCerts(): int
    {
        return $this->_skipCerts;
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        return new self($critical,
            UnspecifiedType::fromDER($data)->asInteger()->intNumber());
    }

    protected function _valueASN1(): Element
    {
        return new Integer($this->_skipCerts);
    }
}
