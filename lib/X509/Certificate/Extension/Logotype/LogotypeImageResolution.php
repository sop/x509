<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use LogicException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;

class LogotypeImageResolution {

    const TAG_NUM_BITS = 1;
    const TAG_TABLE_SIZE = 2;

    /**
     * @var Integer
     */    
    protected $_value;

    /**     
     * @var int
     */
    protected $_type;

    /**     
     * @param int $type 
     *  One of TAG_NUM_BITS, TAG_TABLE_SIZE
     * @return void 
     */
    public function __construct(Integer $value, int $type)
    {  
        $this->_value = $value;
        $this->_type = $type;
    }

    public function value() : Integer {
        return $this->_value;
    }

    public function type() : int {
        return $this->type();
    }

    public static function fromASN1(Sequence $seq) : LogotypeImageResolution {

        /*
        LogotypeImageResolution ::= CHOICE {
            numBits         [1] INTEGER,  
            tableSize       [2] INTEGER }
        */        

        foreach([self::TAG_NUM_BITS, self::TAG_TABLE_SIZE] as $tag){
            if ($seq->hasTagged($tag)) {
                return new LogotypeImageResolution(
                    $seq->getTagged($tag)->asImplicit(Element::TYPE_INTEGER)->asInteger(),
                    $tag
                );
            }
        }
        
        throw new LogicException('Invalid logotype image resolution');
        
                      
    }

    public function toASN1() : Element {        
        return new ImplicitlyTaggedType($this->_type, $this->_value);        
    }
}