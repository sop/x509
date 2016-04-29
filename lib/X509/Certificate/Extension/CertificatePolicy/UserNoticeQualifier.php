<?php

namespace X509\Certificate\Extension\CertificatePolicy;

use ASN1\Element;
use ASN1\Type\Constructed\Sequence;


/**
 * Implements <i>UserNotice</i> ASN.1 type used by
 * 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class UserNoticeQualifier extends PolicyQualifierInfo
{
	/**
	 * Explicit notice text.
	 *
	 * @var DisplayText $_text
	 */
	protected $_text;
	
	/**
	 * Notice reference.
	 *
	 * @var NoticeReference $_ref
	 */
	protected $_ref;
	
	/**
	 * Constructor
	 *
	 * @param DisplayText|null $text
	 * @param NoticeReference|null $ref
	 */
	public function __construct(DisplayText $text = null, 
			NoticeReference $ref = null) {
		$this->_oid = self::OID_UNOTICE;
		$this->_text = $text;
		$this->_ref = $ref;
	}
	
	/**
	 * Initialize from ASN.1.
	 *
	 * @param Sequence $seq
	 * @return self
	 */
	protected static function _fromASN1(Sequence $seq) {
		$ref = null;
		$text = null;
		$idx = 0;
		if ($seq->has($idx, Element::TYPE_SEQUENCE)) {
			$ref = NoticeReference::fromASN1($seq->at($idx++));
		}
		if ($seq->has($idx, Element::TYPE_STRING)) {
			$text = DisplayText::fromASN1($seq->at($idx));
		}
		return new self($text, $ref);
	}
	
	/**
	 * Whether explicit text is present.
	 */
	public function hasExplicitText() {
		return isset($this->_text);
	}
	
	/**
	 * Get explicit text.
	 *
	 * @return DisplayText
	 */
	public function explicitText() {
		if (!$this->hasExplicitText()) {
			throw new \LogicException("No explicit text");
		}
		return $this->_text;
	}
	
	/**
	 * Whether notice reference is present.
	 *
	 * @return bool
	 */
	public function hasNoticeRef() {
		return isset($this->_ref);
	}
	
	/**
	 * Get notice reference.
	 *
	 * @throws \RuntimeException
	 * @return NoticeReference
	 */
	public function noticeRef() {
		if (!$this->hasNoticeRef()) {
			throw new \LogicException("No notice reference");
		}
		return $this->_ref;
	}
	
	protected function _qualifierASN1() {
		$elements = array();
		if (isset($this->_ref)) {
			$elements[] = $this->_ref->toASN1();
		}
		if (isset($this->_text)) {
			$elements[] = $this->_text->toASN1();
		}
		return new Sequence(...$elements);
	}
}
