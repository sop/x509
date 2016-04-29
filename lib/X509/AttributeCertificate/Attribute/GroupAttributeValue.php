<?php

namespace X509\AttributeCertificate\Attribute;

use X501\ASN1\AttributeType;


/**
 * Implements value for 'Group' attribute.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.4.4
 */
class GroupAttributeValue extends IetfAttrSyntax
{
	/**
	 * Constructor
	 *
	 * @param IetfAttrValue ...$values
	 */
	public function __construct(IetfAttrValue ...$values) {
		parent::__construct(...$values);
		$this->_oid = AttributeType::OID_GROUP;
	}
}
