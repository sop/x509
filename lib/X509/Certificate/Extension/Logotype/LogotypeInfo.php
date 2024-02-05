<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;

abstract class LogotypeInfo
{
    public const TAG_DIRECT = 0;
    public const TAG_INDIRECT = 1;

    public static function fromASN1(Sequence $seq): LogotypeInfo
    {
        /*
        LogotypeInfo ::= CHOICE {
            direct          [0] LogotypeData,
            indirect        [1] LogotypeReference }
        */

        if ($seq->hasTagged(self::TAG_DIRECT)) {
            return LogotypeData::fromASN1($seq->getTagged(self::TAG_DIRECT)->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
        }
        if ($seq->hasTagged(self::TAG_INDIRECT)) {
            return LogotypeReference::fromASN1($seq->getTagged(self::TAG_DIRECT)->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
        }

        throw new \LogicException('Invalid logotype info.');
    }

    abstract public function toASN1(): Element;
}
