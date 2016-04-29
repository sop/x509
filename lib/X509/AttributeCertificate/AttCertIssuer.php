<?php

namespace X509\AttributeCertificate;

use ASN1\Element;
use X501\ASN1\Name;
use X509\GeneralName\DirectoryName;
use X509\GeneralName\GeneralNames;


/**
 * Base class implementing <i>AttCertIssuer</i> ASN.1 CHOICE type.
 *
 * @link https://tools.ietf.org/html/rfc5755#section-4.1
 */
abstract class AttCertIssuer
{
	/**
	 * Generate ASN.1 element.
	 *
	 * @return Element
	 */
	abstract public function toASN1();
	
	/**
	 * Initialize from distinguished name.
	 *
	 * This conforms to RFC 5755 which states that only v2Form must be used,
	 * and issuerName must contain exactly one GeneralName of DirectoryName
	 * type.
	 *
	 * @link https://tools.ietf.org/html/rfc5755#section-4.2.3
	 * @param Name $name
	 * @return self
	 */
	public static function fromName(Name $name) {
		return new V2Form(new GeneralNames(new DirectoryName($name)));
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Element $el CHOICE
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromASN1(Element $el) {
		if (!$el->isTagged()) {
			throw new \UnexpectedValueException("v1Form issuer not supported");
		}
		switch ($el->tag()) {
		case 0:
			return V2Form::_fromASN1($el->implicit(Element::TYPE_SEQUENCE));
		}
		throw new \UnexpectedValueException("Unsupported issuer type");
	}
}
