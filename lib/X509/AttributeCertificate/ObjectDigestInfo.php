<?php

declare(strict_types = 1);

namespace Sop\X509\AttributeCertificate;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\Enumerated;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;

/**
 * Implements *ObjectDigestInfo* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.1
 * @see https://tools.ietf.org/html/rfc5755#section-7.3
 */
class ObjectDigestInfo
{
    public const TYPE_PUBLIC_KEY = 0;
    public const TYPE_PUBLIC_KEY_CERT = 1;
    public const TYPE_OTHER_OBJECT_TYPES = 2;

    /**
     * Object type.
     *
     * @var int
     */
    protected $_digestedObjectType;

    /**
     * OID of other object type.
     *
     * @var null|string
     */
    protected $_otherObjectTypeID;

    /**
     * Digest algorithm.
     *
     * @var AlgorithmIdentifierType
     */
    protected $_digestAlgorithm;

    /**
     * Object digest.
     *
     * @var BitString
     */
    protected $_objectDigest;

    /**
     * Constructor.
     */
    public function __construct(int $type, AlgorithmIdentifierType $algo,
        BitString $digest)
    {
        $this->_digestedObjectType = $type;
        $this->_otherObjectTypeID = null;
        $this->_digestAlgorithm = $algo;
        $this->_objectDigest = $digest;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): ObjectDigestInfo
    {
        $idx = 0;
        $oid = null;
        $type = $seq->at($idx++)->asEnumerated()->intNumber();
        if ($seq->has($idx, Element::TYPE_OBJECT_IDENTIFIER)) {
            $oid = $seq->at($idx++)->asObjectIdentifier()->oid();
        }
        $algo = AlgorithmIdentifier::fromASN1($seq->at($idx++)->asSequence());
        $digest = $seq->at($idx)->asBitString();
        $obj = new self($type, $algo, $digest);
        $obj->_otherObjectTypeID = $oid;
        return $obj;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [new Enumerated($this->_digestedObjectType)];
        if (isset($this->_otherObjectTypeID)) {
            $elements[] = new ObjectIdentifier($this->_otherObjectTypeID);
        }
        $elements[] = $this->_digestAlgorithm->toASN1();
        $elements[] = $this->_objectDigest;
        return new Sequence(...$elements);
    }
}
