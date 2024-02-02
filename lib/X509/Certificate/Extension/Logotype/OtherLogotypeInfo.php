<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;

class OtherLogotypeInfo {

    /**     
     * @var ObjectIdentifier
     */
    protected $_logotypeType;

    /**     
     * @var LogotypeInfo
     */
    protected $_info;

    public function __construct(ObjectIdentifier $logotypeType, LogotypeInfo $info)
    {
        $this->_logotypeType = $logotypeType;
        $this->_info = $info;        
    }


    public function logotypeType() : ObjectIdentifier {
        return $this->_logotypeType;
    }

    public function info() : LogotypeInfo {
        return $this->_info;
    }

    public static function fromASN1(Sequence $seq) : OtherLogotypeInfo {                
        /*
        OtherLogotypeInfo ::= SEQUENCE {
            logotypeType    OBJECT IDENTIFIER,
            info            LogotypeInfo }
        */

        return new OtherLogotypeInfo(
            $seq->at(0)->expectType(Element::TYPE_OBJECT_IDENTIFIER),
            LogotypeInfo::fromASN1($seq->at(1)->expectType(Element::TYPE_SEQUENCE))                        
        );        
    }

    public function toASN1() : Sequence {
        return new Sequence($this->_logotypeType, $this->_info->toASN1());
    }
}