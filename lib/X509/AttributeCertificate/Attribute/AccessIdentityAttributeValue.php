<?php

namespace X509\AttributeCertificate\Attribute;

use X501\ASN1\AttributeType;
use X509\GeneralName\GeneralName;


/**
 * Implements value for 'Access Identity' attribute.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.2
 */
class AccessIdentityAttributeValue extends SvceAuthInfo
{
	/**
	 * Constructor
	 *
	 * @param GeneralName $service
	 * @param GeneralName $ident
	 */
	public function __construct(GeneralName $service, GeneralName $ident) {
		parent::__construct($service, $ident, null);
		$this->_oid = AttributeType::OID_ACCESS_IDENTITY;
	}
}
