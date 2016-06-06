<?php

namespace X509\Certificate;

use ASN1\Type\Constructed\Sequence;


/**
 * Implements <i>Validity</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.1.2.5
 */
class Validity
{
	/**
	 * Not before time
	 *
	 * @var Time $_notBefore
	 */
	protected $_notBefore;
	
	/**
	 * Not after time
	 *
	 * @var Time $_notAfter
	 */
	protected $_notAfter;
	
	/**
	 * Constructor
	 *
	 * @param Time $not_before
	 * @param Time $not_after
	 */
	public function __construct(Time $not_before, Time $not_after) {
		$this->_notBefore = $not_before;
		$this->_notAfter = $not_after;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 */
	public static function fromASN1(Sequence $seq) {
		$nb = Time::fromASN1($seq->at(0)->asTime());
		$na = Time::fromASN1($seq->at(1)->asTime());
		return new self($nb, $na);
	}
	
	/**
	 * Initialize from date strings.
	 *
	 * @param string|null $nb_date Not before date
	 * @param string|null $na_date Not after date
	 * @param string|null $tz Timezone string
	 * @return self
	 */
	public static function fromStrings($nb_date, $na_date, $tz = null) {
		return new self(Time::fromString($nb_date, $tz), 
			Time::fromString($na_date, $tz));
	}
	
	/**
	 * Get not before time.
	 *
	 * @return Time
	 */
	public function notBefore() {
		return $this->_notBefore;
	}
	
	/**
	 * Get not after time.
	 *
	 * @return Time
	 */
	public function notAfter() {
		return $this->_notAfter;
	}
	
	/**
	 * Generate ASN.1 structure.
	 *
	 * @return Sequence
	 */
	public function toASN1() {
		return new Sequence($this->_notBefore->toASN1(), 
			$this->_notAfter->toASN1());
	}
}
