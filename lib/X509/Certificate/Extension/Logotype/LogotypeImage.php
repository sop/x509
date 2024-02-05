<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;

class LogotypeImage
{
    /**
     * @var LogotypeDetails
     */
    protected $_imageDetails;

    /**
     * @var null|LogotypeImageInfo
     */
    protected $_imageInfo;

    public function __construct(LogotypeDetails $imageDetails, ?LogotypeImageInfo $imageInfo = null)
    {
        $this->_imageDetails = $imageDetails;
        $this->_imageInfo = $imageInfo;
    }

    public function imageDetails(): LogotypeDetails
    {
        return $this->_imageDetails;
    }

    /**
     * @return null|LogotypeImageInfo
     */
    public function imageInfo(): mixed
    {
        return $this->_imageInfo;
    }

    public static function fromASN1(Sequence $seq): LogotypeImage
    {
        /*
        LogotypeImage ::= SEQUENCE {
            imageDetails    LogotypeDetails,
            imageInfo       LogotypeImageInfo OPTIONAL }
        */

        return new LogotypeImage(
            LogotypeDetails::fromASN1($seq->at(0)->asSequence()),
            $seq->has(1) ? LogotypeImageInfo::fromASN1($seq->at(1)->asSequence()) : null
        );
    }

    public function toASN1(): Element
    {
        $elements = [$this->_imageDetails->toASN1()];

        if ($this->_imageInfo) {
            $elements[] = $this->_imageInfo->toASN1();
        }

        return new Sequence(...$elements);
    }
}
