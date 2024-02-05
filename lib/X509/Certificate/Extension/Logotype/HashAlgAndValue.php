<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;

class HashAlgAndValue
{
    /**
     * @var AlgorithmIdentifier
     */
    protected $_hashAlg;

    /**
     * @var OctetString
     */
    protected $_hashValue;

    public function __construct(AlgorithmIdentifier $hashAlg, OctetString $hashValue)
    {
        $this->_hashAlg = $hashAlg;
        $this->_hashValue = $hashValue;
    }

    public function hashAlg(): AlgorithmIdentifier
    {
        return $this->_hashAlg;
    }

    public function hashValue(): OctetString
    {
        return $this->_hashValue;
    }

    public function toASN1(): Sequence
    {
        return new Sequence($this->_hashAlg->toASN1(), $this->hashValue());
    }

    public static function fromASN1(Sequence $seq): HashAlgAndValue
    {
        return new HashAlgAndValue(
            AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence()),
            $seq->at(1)->asOctetString()
        );
    }
}
