<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;

class LogotypeImageInfo  {

    const LogotypeImageTypeGrayScale = 0;
    const LogotypeImageTypeColor = 1;

    /**     
     * @var Integer
     */
    protected $_type;

    /**     
     * @var Integer
     */
    protected $_fileSize;

    /**     
     * @var Integer
     */
    protected $_xSize;

    /**     
     * @var Integer
     */
    protected $_ySize;

    /**     
     * @var null|LogotypeImageResolution
     */
    protected $_resolution;

    /**     
     * @var null|IA5String
     */
    protected $_language;

    public function __construct(
        Integer $type, 
        Integer $fileSize, 
        Integer $xSize, 
        Integer $ySize, 
        ?LogotypeImageResolution $resolution,
        ?IA5String $language)
    {
        $this->_type = $type;    
        $this->_fileSize = $fileSize;
        $this->_xSize = $xSize;
        $this->_ySize = $ySize;
        $this->_resolution = $resolution;
        $this->_language = $language;
    }

    public function type() : Integer {
        return $this->_type;
    }

    public function fileSize() : Integer {
        return $this->_fileSize;
    }

    public function xSize() : Integer {
        return $this->_xSize;
    }

    public function ySize() : Integer {
        return $this->_ySize;
    }

    /**     
     * @return null|LogotypeImageResolution
     */
    public function resolution()  {
        return $this->_resolution;
    }

    /**     
     * @return null|IA5String 
     */
    public function language() {
        return $this->_ySize;
    }


    public static function fromASN1(Sequence $seq) : LogotypeImageInfo {
        /*
        LogotypeImageInfo ::= SEQUENCE {
            type            [0] LogotypeImageType DEFAULT color,
            fileSize        INTEGER,  -- In octets, 0=unspecified
            xSize           INTEGER,  -- Horizontal size in pixels
            ySize           INTEGER,  -- Vertical size in pixels
            resolution      LogotypeImageResolution OPTIONAL,
            language        [4] IA5String OPTIONAL }

        LogotypeImageType ::= INTEGER { grayScale(0), color(1) }
        */

        $type = $seq->hasTagged(0) ? $seq->getTagged(0)->asUnspecified()->asInteger()->intNumber() : new Integer(static::LogotypeImageTypeColor);

        $offset = $seq->hasTagged(0) ? 0 : 1;        

        $fileSize = $seq->at(1 - $offset)->asInteger();
        $xSize = $seq->at(2 - $offset)->asInteger();
        $ySize = $seq->at(3 - $offset)->asInteger();

        if ($seq->has(4 - $offset)) {
            $resolution = LogotypeImageResolution::fromASN1($seq->at(4 - $offset)->asSequence());
        }
        else {
            $resolution = null;
        }

        $language = $seq->hasTagged(5) ? $seq->getTagged(5)->asUnspecified()->asIA5String() : null;

        return new LogotypeImageInfo($type, $fileSize, $xSize, $ySize, $resolution, $language);
    }

    public function toASN1() : Sequence {
        $elements = [];        
        
        if ($this->_type->intNumber() != static::LogotypeImageTypeColor) {
            $elements[] = new ExplicitlyTaggedType(0, $this->_type);
        }

        $elements += [$this->_fileSize, $this->_xSize, $this->_ySize];

        if ($this->_resolution) {
            $elements[] = $this->_resolution;
        }

        if ($this->_language) {
            $elements[] = new ExplicitlyTaggedType(4, $this->_language);
        }

        return new Sequence(...$elements);
    }
}