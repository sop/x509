<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\CertificatePolicy;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements *UserNotice* ASN.1 type used by 'Certificate Policies'
 * certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class UserNoticeQualifier extends PolicyQualifierInfo
{
    /**
     * Explicit notice text.
     *
     * @var null|DisplayText
     */
    protected $_text;

    /**
     * Notice reference.
     *
     * @var null|NoticeReference
     */
    protected $_ref;

    /**
     * Constructor.
     */
    public function __construct(?DisplayText $text = null,
        ?NoticeReference $ref = null)
    {
        $this->_oid = self::OID_UNOTICE;
        $this->_text = $text;
        $this->_ref = $ref;
    }

    /**
     * @return self
     */
    public static function fromQualifierASN1(UnspecifiedType $el): PolicyQualifierInfo
    {
        $seq = $el->asSequence();
        $ref = null;
        $text = null;
        $idx = 0;
        if ($seq->has($idx, Element::TYPE_SEQUENCE)) {
            $ref = NoticeReference::fromASN1($seq->at($idx++)->asSequence());
        }
        if ($seq->has($idx, Element::TYPE_STRING)) {
            $text = DisplayText::fromASN1($seq->at($idx)->asString());
        }
        return new self($text, $ref);
    }

    /**
     * Whether explicit text is present.
     */
    public function hasExplicitText(): bool
    {
        return isset($this->_text);
    }

    /**
     * Get explicit text.
     *
     * @throws \LogicException If not set
     */
    public function explicitText(): DisplayText
    {
        if (!$this->hasExplicitText()) {
            throw new \LogicException('explicitText not set.');
        }
        return $this->_text;
    }

    /**
     * Whether notice reference is present.
     */
    public function hasNoticeRef(): bool
    {
        return isset($this->_ref);
    }

    /**
     * Get notice reference.
     *
     * @throws \LogicException If not set
     */
    public function noticeRef(): NoticeReference
    {
        if (!$this->hasNoticeRef()) {
            throw new \LogicException('noticeRef not set.');
        }
        return $this->_ref;
    }

    protected function _qualifierASN1(): Element
    {
        $elements = [];
        if (isset($this->_ref)) {
            $elements[] = $this->_ref->toASN1();
        }
        if (isset($this->_text)) {
            $elements[] = $this->_text->toASN1();
        }
        return new Sequence(...$elements);
    }
}
