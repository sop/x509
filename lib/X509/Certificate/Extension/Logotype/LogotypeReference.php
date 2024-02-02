<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use LogicException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;

class LogotypeReference extends LogotypeInfo {

    /**     
     * @var array<HashAlgAndValue>
     */
    protected $_refStructHash;

    /**     
     * @var array<IA5String>
     */
    protected $_refStructURI;

    /**     
     * @param array<HashAlgAndValue> $refStructHash 
     * @param array<IA5String> $refStructURI      
     */
    public function __construct(array $refStructHash, array $refStructURI)
    {
        $this->_refStructHash = $refStructHash;
        $this->_refStructURI = $refStructURI;
    }

    /**     
     * @return array<HashAlgAndValue>
     */
    public function refStructHash() : array {
        return $this->_refStructHash;
    }

    /**     
     * @return array<IA5String>
     */
    public function refStructURI() : array {
        return $this->_refStructURI;
    }

    public function toASN1() : Element {        
        return new ImplicitlyTaggedType(
            static::TAG_INDIRECT, 
            new Sequence(new Sequence(...$this->_refStructHash), new Sequence(...$this->_refStructURI))
        );
    }

    public static function fromASN1(Sequence $seq) : LogotypeInfo {

        /*
        LogotypeReference ::= SEQUENCE {
            refStructHash   SEQUENCE SIZE (1..MAX) OF HashAlgAndValue,
            refStructURI    SEQUENCE SIZE (1..MAX) OF IA5String }
        */

        $refStructHash = $seq->at(0)->asSequence();

        if ($refStructHash->count() == 0) {
            throw new LogicException('LogotypeReference.refStructHash is empty');
        }
        
        $refStructURI = $seq->at(1)->asSequence();      

        if ($refStructURI->count() != $refStructHash->count()) {
            throw new LogicException('LogotypeReference.refStructHash and LogotypeReference.refStructURI contains a different number of elements');
        }

        $hashes = array_map(function (UnspecifiedType $element) {
            return HashAlgAndValue::fromASN1($element->asSequence());
        }, $refStructHash->elements());

        $uris = array_map(function (UnspecifiedType $element) {
            return $element->asIA5String();
        }, $refStructURI->elements());

        return new LogotypeReference($hashes, $uris); 
    }
}