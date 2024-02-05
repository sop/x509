<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\Certificate\Extension\AccessDescription\AccessDescription;
use Sop\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;

/**
 * Implements 'Authority Information Access' extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.1
 */
class AuthorityInformationAccessExtension extends Extension implements \Countable, \IteratorAggregate
{
    /**
     * Access descriptions.
     *
     * @var AuthorityAccessDescription[]
     */
    private $_accessDescriptions;

    /**
     * Constructor.
     */
    public function __construct(bool $critical, AuthorityAccessDescription ...$access)
    {
        parent::__construct(self::OID_AUTHORITY_INFORMATION_ACCESS, $critical);
        $this->_accessDescriptions = $access;
    }

    /**
     * Get the access descriptions.
     *
     * @return AuthorityAccessDescription[]
     */
    public function accessDescriptions(): array
    {
        return $this->_accessDescriptions;
    }

    /**
     * Get the number of access descriptions.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_accessDescriptions);
    }

    /**
     * Get iterator for access descriptions.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return \ArrayIterator List of AuthorityAccessDescription objects
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_accessDescriptions);
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $access = array_map(
            function (UnspecifiedType $el) {
                return AuthorityAccessDescription::fromASN1($el->asSequence());
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        return new self($critical, ...$access);
    }

    protected function _valueASN1(): Element
    {
        $elements = array_map(
            function (AccessDescription $access) {
                return $access->toASN1();
            }, $this->_accessDescriptions);
        return new Sequence(...$elements);
    }
}
