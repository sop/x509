<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\Logotype;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;

class LogotypeData extends LogotypeInfo
{
    public const TAG_AUDIO = 1;

    /**
     * @var array<LogotypeImage>
     */
    protected $_image = [];

    /**
     * @var array<LogotypeAudio>
     */
    protected $_audio = [];

    /**
     * @param array<LogotypeImage> $image
     * @param array<LogotypeAudio> $audio
     */
    public function __construct(
        array $image = [],
        array $audio = [])
    {
        $this->_image = $image;
        $this->_audio = $audio;
    }

    /**
     * @return array<LogotypeImage>
     */
    public function image(): array
    {
        return $this->_image;
    }

    /**
     * @return array<LogotypeAudio>
     */
    public function audio(): array
    {
        return $this->_audio;
    }

    public static function fromASN1(Sequence $seq): LogotypeInfo
    {
        /*
        LogotypeData ::= SEQUENCE {
            image SEQUENCE OF LogotypeImage OPTIONAL,
            audio [1] SEQUENCE OF LogotypeAudio OPTIONAL }
        */

        if (0 == $seq->count()) {
            throw new \LogicException('At least one logotype data must be present.');
        }

        $images = [];
        $audios = [];

        foreach ($seq->elements() as $element) {
            if ($element->isTagged() && (self::TAG_AUDIO == $element->tag())) {
                $audios = array_map(function (UnspecifiedType $element) {
                    return LogotypeAudio::fromASN1($element->asSequence());
                }, $element->asSequence()->elements());
            } else {
                $images = array_map(function (UnspecifiedType $element) {
                    return LogotypeImage::fromASN1($element->asSequence());
                }, $element->asSequence()->elements());
            }
        }

        return new LogotypeData($images, $audios);
    }

    public function toASN1(): Element
    {
        $elements = [];

        $images = array_map(function (LogotypeImage $image) {
            return $image->toASN1();
        }, $this->_image);

        if (count($images) > 0) {
            $elements[] = new Sequence(...$images);
        }

        $audios = array_map(function (LogotypeAudio $audio) {
            return $audio->toASN1();
        }, $this->_audio);

        if (count($audios) > 0) {
            $elements[] = new ImplicitlyTaggedType(static::TAG_AUDIO, new Sequence(...$audios));
        }

        return new ImplicitlyTaggedType(static::TAG_DIRECT, new Sequence(...$elements));
    }
}
