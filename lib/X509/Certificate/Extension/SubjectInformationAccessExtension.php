<?php
declare(strict_types = 1);

namespace X509\Certificate\Extension;

use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use X509\Certificate\Extension\AccessDescription\AccessDescription;
use X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;

/**
 * Implements 'Subject Information Access' extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.2.2
 */
class SubjectInformationAccessExtension extends Extension implements 
    \Countable,
    \IteratorAggregate
{
    /**
     * Access descriptions.
     *
     * @var SubjectAccessDescription[]
     */
    private $_accessDescriptions;
    
    /**
     * Constructor.
     *
     * @param bool $critical
     * @param SubjectAccessDescription ...$access
     */
    public function __construct(bool $critical,
        SubjectAccessDescription ...$access)
    {
        parent::__construct(self::OID_SUBJECT_INFORMATION_ACCESS, $critical);
        $this->_accessDescriptions = $access;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return self
     */
    protected static function _fromDER(string $data, bool $critical): self
    {
        $access = array_map(
            function (UnspecifiedType $el) {
                return SubjectAccessDescription::fromASN1($el->asSequence());
            }, UnspecifiedType::fromDER($data)->asSequence()->elements());
        return new self($critical, ...$access);
    }
    
    /**
     * Get the access descriptions.
     *
     * @return SubjectAccessDescription[]
     */
    public function accessDescriptions(): array
    {
        return $this->_accessDescriptions;
    }
    
    /**
     *
     * {@inheritdoc}
     * @return Sequence
     */
    protected function _valueASN1(): Sequence
    {
        $elements = array_map(
            function (AccessDescription $access) {
                return $access->toASN1();
            }, $this->_accessDescriptions);
        return new Sequence(...$elements);
    }
    
    /**
     * Get the number of access descriptions.
     *
     * @see \Countable::count()
     * @return int
     */
    public function count(): int
    {
        return count($this->_accessDescriptions);
    }
    
    /**
     * Get iterator for access descriptions.
     *
     * @see \IteratorAggregate::getIterator()
     * @return \ArrayIterator List of SubjectAccessDescription objects
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->_accessDescriptions);
    }
}
