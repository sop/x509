<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\UnspecifiedType;

class LogotypeDetails  {

    /**     
     * @var IA5String
     */
    protected $_mediaType;

    /**     
     * @var array<HashAlgAndValue>
     */
    protected $_logotypeHash;

    /**     
     * @var array<IA5String>
     */
    protected $_logotypeUri;

    /**          
     * @param array<HashAlgAndValue> $logotypeHash 
     * @param array<IA5String> $_logotypeUri 
     */
    public function __construct(IA5String $mediaType, array $logotypeHash, array $logotypeUri)
    {
        $this->_mediaType = $mediaType;
        $this->_logotypeHash = $logotypeHash;
        $this->_logotypeUri = $logotypeUri;
    }

    public function mediaType() : IA5String {
        return $this->_mediaType;
    }

    /**     
     * @return array<HashAlgAndValue> 
     */
    public function logotypeHash() : array {
        return $this->_logotypeHash;
    }

    /**     
     * @return array<IA5String> 
     */
    public function logotypeUri() : array {
        return $this->_logotypeUri;
    }    

    public static function fromASN1(Sequence $seq) : LogotypeDetails {
        /*
        LogotypeDetails ::= SEQUENCE {
            mediaType       IA5String,                                    
            logotypeHash    SEQUENCE SIZE (1..MAX) OF HashAlgAndValue,
            logotypeURI     SEQUENCE SIZE (1..MAX) OF IA5String }
         */
        $mediaType = $seq->at(0)->asIA5String();

        $hashes = array_map(function (UnspecifiedType $element) {
            return HashAlgAndValue::fromASN1($element->asSequence());
        }, $seq->at(1)->asSequence()->elements());


        $uris = array_map(function (UnspecifiedType $element) {
            return $element->asIA5String();
        }, $seq->at(2)->asSequence()->elements());

        return new LogotypeDetails($mediaType, $hashes, $uris);
    }

    public function toASN1() : Element {
        $elements = [$this->_mediaType];
        
        $elements[] = new Sequence(
            ...array_map(
                function(HashAlgAndValue $hash) : Sequence {
                    return $hash->toASN1();
                }, 
                $this->_logotypeHash
            )                
        );
             
        $elements[] = new Sequence(...$this->_logotypeUri);
                
        return new Sequence(...$elements);
    }
}