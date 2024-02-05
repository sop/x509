<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\AccessDescription;

/**
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.1
 */
class AuthorityAccessDescription extends AccessDescription
{
    /**
     * Access method OID's.
     *
     * @var string
     */
    public const OID_METHOD_OSCP = '1.3.6.1.5.5.7.48.1';
    public const OID_METHOD_CA_ISSUERS = '1.3.6.1.5.5.7.48.2';

    /**
     * Check whether access method is OSCP.
     */
    public function isOSCPMethod(): bool
    {
        return self::OID_METHOD_OSCP === $this->_accessMethod;
    }

    /**
     * Check whether access method is CA issuers.
     */
    public function isCAIssuersMethod(): bool
    {
        return self::OID_METHOD_CA_ISSUERS === $this->_accessMethod;
    }
}
