<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;

class LogotypeAudioInfo {

    /**     
     * @var Integer
     */
    protected $_fileSize;

    /**     
     * @var Integer
     */
    protected $_playTime;

    /**     
     * @var Integer
     */
    protected $_channels;

    /**     
     * @var null|Integer
     */
    protected $_sampleRate;

    /**     
     * @var null|IA5String
     */
    protected $_language;

    public function __construct(Integer $fileSize, Integer $playTime, Integer $channels, ?Integer $sampleRate, ?IA5String $language)
    {
        $this->_fileSize = $fileSize;    
        $this->_playTime = $playTime;
        $this->_channels = $channels;
        $this->_sampleRate = $sampleRate;
        $this->_language = $language;
    }

    public static function fromASN1(Sequence $seq) : LogotypeAudioInfo {                
        /*
        LogotypeAudioInfo ::= SEQUENCE {
            fileSize        INTEGER,  
            playTime        INTEGER,  
            channels        INTEGER,                                      
            sampleRate      [3] INTEGER OPTIONAL,  
            language        [4] IA5String OPTIONAL }
        */

        $fileSize = $seq->at(0)->asInteger();
        $playTime = $seq->at(1)->asInteger();
        $channels = $seq->at(2)->asInteger();
        $sampleRate = $seq->hasTagged(3) ? $seq->getTagged(3)->asUnspecified()->asInteger() : null;
        $language = $seq->hasTagged(4) ? $seq->getTagged(4)->asUnspecified()->asIA5String() : null;

        return new LogotypeAudioInfo($fileSize,$playTime,$channels, $sampleRate,$language);        
    }

    public function toASN1() : Sequence {
        $elements = [$this->_fileSize, $this->_playTime, $this->_channels];

        if ($this->_sampleRate) {
            $elements[] = new ImplicitlyTaggedType(3, $this->_sampleRate);            
        }

        if ($this->_language) {
            $elements[] = new ImplicitlyTaggedType(4, $this->_language);            
        }

        return new Sequence(...$elements);
    }
}