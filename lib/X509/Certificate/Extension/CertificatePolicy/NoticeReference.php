<?php

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\Integer;


/**
 * Implements <i>NoticeReference</i> ASN.1 type used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class NoticeReference
{
	/**
	 * Organization.
	 *
	 * @var DisplayText $_organization
	 */
	protected $_organization;
	
	/**
	 * Notification reference numbers.
	 *
	 * @var int[] $_numbers
	 */
	protected $_numbers;
	
	/**
	 * Constructor
	 *
	 * @param DisplayText $organization
	 * @param int ...$numbers
	 */
	public function __construct(DisplayText $organization, ...$numbers) {
		$this->_organization = $organization;
		$this->_numbers = $numbers;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	public static function fromASN1(Sequence $seq) {
		$org = DisplayText::fromASN1($seq->at(0, Element::TYPE_STRING));
		$numbers = array_map(
			function (Element $el) {
				return $el->expectType(Element::TYPE_INTEGER)->number();
			}, $seq->at(1, Element::TYPE_SEQUENCE)->elements());
		return new self($org, ...$numbers);
	}
	
	/**
	 * Get reference organization.
	 *
	 * @return DisplayText
	 */
	public function organization() {
		return $this->_organization;
	}
	
	/**
	 * Get reference numbers.
	 *
	 * @return int[]
	 */
	public function numbers() {
		return $this->_numbers;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		$org = $this->_organization->toASN1();
		$nums = array_map(
			function ($number) {
				return new Integer($number);
			}, $this->_numbers);
		return new Sequence($org, new Sequence(...$nums));
	}
}
