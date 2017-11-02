<?php

declare(strict_types=1);

namespace X509\AttributeCertificate\Attribute;

use X509\GeneralName\GeneralName;

/**
 * Implements value for 'Access Identity' attribute.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.2
 */
class AccessIdentityAttributeValue extends SvceAuthInfo
{
    const OID = "1.3.6.1.5.5.7.10.2";

    /**
     * Constructor.
     *
     * @param GeneralName $service
     * @param GeneralName $ident
     */
    public function __construct(GeneralName $service, GeneralName $ident)
    {
        parent::__construct($service, $ident, null);
        $this->_oid = self::OID;
    }
}
