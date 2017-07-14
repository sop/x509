<?php

namespace X509\AttributeCertificate\Attribute;

/**
 * Implements value for 'Charging Identity' attribute.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.3
 */
class ChargingIdentityAttributeValue extends IetfAttrSyntax
{
    const OID = "1.3.6.1.5.5.7.10.3";
    
    /**
     * Constructor.
     *
     * @param IetfAttrValue ...$values
     */
    public function __construct(IetfAttrValue ...$values)
    {
        parent::__construct(...$values);
        $this->_oid = self::OID;
    }
}
