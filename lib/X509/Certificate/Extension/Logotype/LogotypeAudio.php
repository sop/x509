<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Type\Constructed\Sequence;

class LogotypeAudio
{
    /**
     * @var LogotypeDetails
     */
    protected $_audioDetails;

    /**
     * @var null|LogotypeAudioInfo
     */
    protected $_audioInfo;

    public function __construct(LogotypeDetails $audioDetails, ?LogotypeAudioInfo $audioInfo)
    {
        $this->_audioDetails = $audioDetails;
        $this->_audioInfo = $audioInfo;
    }

    public function audioDetails(): LogotypeDetails
    {
        return $this->_audioDetails;
    }

    /**
     * @return null|LogotypeDetails
     */
    public function audioInfo()
    {
        return $this->_audioInfo;
    }

    public static function fromASN1(Sequence $seq): LogotypeAudio
    {
        /*
        LogotypeAudio ::= SEQUENCE {
            audioDetails    LogotypeDetails,
            audioInfo       LogotypeAudioInfo OPTIONAL }
        */

        return new LogotypeAudio(
            LogotypeDetails::fromASN1($seq->at(0)->asSequence()),
            $seq->has(1) ? LogotypeAudioInfo::fromASN1($seq->at(1)->asSequence()) : null
        );
    }

    public function toASN1(): Sequence
    {
        $elements = [$this->_audioDetails->toASN1()];

        if ($this->_audioInfo) {
            $elements[] = $this->_audioInfo->toASN1();
        }

        return new Sequence(...$elements);
    }
}
