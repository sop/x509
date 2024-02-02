<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension;

use LogicException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\Certificate\Extension\Logotype\LogotypeInfo;
use Sop\X509\Certificate\Extension\Logotype\OtherLogotypeInfo;

/**
 * Implements 'Logotype' certificate extension.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9399#section-4.1
 */

class LogotypeExtension extends Extension {

    /**     
     * @var array<LogotypeInfo>
     */
    protected $_communityLogos;

    /**    
     * @var null|LogotypeInfo
     */
    protected $_issuerLogo;

    /**    
     * @var null|LogotypeInfo
     */
    protected $_subjectLogo;

    /**     
     * @var array<LogotypeInfo>
     */
    protected $_otherLogos;

    /**
     
     * @param array<LogotypeInfo> $communityLogos 
     * @param null|LogotypeInfo $issuerLogo 
     * @param null|LogotypeInfo $subjectLogo 
     * @param array<LogotypeInfo> $otherLogos      
     */    
    public function __construct(
        array $communityLogos = [],
        ?LogotypeInfo $issuerLogo = null, 
        ?LogotypeInfo $subjectLogo = null, 
        array $otherLogos = [])    
    {
        parent::__construct(self::OID_LOGOTYPE, false);

        $this->_communityLogos = $communityLogos;
        $this->_issuerLogo = $issuerLogo;
        $this->_subjectLogo = $subjectLogo;
        $this->_otherLogos = $otherLogos;
    }

    /**     
     * @return array<LogotypeInfo>
     */
    public function communityLogos() : array {
        return $this->_communityLogos;
    }

    /**     
     * @return null|LogotypeInfo
     */
    public function issuerLogo() : mixed {
        return $this->_issuerLogo;
    }

    /**     
     * @return null|LogotypeInfo
     */
    public function subjectLogo() : mixed {
        return $this->_subjectLogo;
    }

    /**     
     * @return array<LogotypeInfo>
     */
    public function otherLogos() : array {
        return $this->_otherLogos;
    }

    protected function _valueASN1(): Element {         
        $communityLogos = array_map(function (LogotypeInfo $logo) {
            return $logo->toASN1();
        }, $this->_communityLogos);

        $otherLogos = array_map(function (LogotypeInfo $logo) {
            return $logo->toASN1();
        }, $this->_otherLogos);

        $elements = [];

        if (count($communityLogos) > 0) {
            $elements[] = new ExplicitlyTaggedType(0, new Sequence(...$communityLogos));
        }

        if ($this->_issuerLogo) {
            $elements[] = new ExplicitlyTaggedType(1, $this->_issuerLogo->toASN1());
        }

        if ($this->_subjectLogo) {
            $elements[] = new ExplicitlyTaggedType(2, $this->_subjectLogo->toASN1());
        }

        if (count($otherLogos) > 0) {
            $elements[] = new ExplicitlyTaggedType(3, new Sequence(...$otherLogos));
        }

        return new Sequence(...$elements);
    }

    /**
     * {@inheritdoc}
     * 
     * @throws LogicException
     */
    protected static function _fromDER(string $data, bool $critical): Extension
    {
        if ($critical) {
            throw new LogicException("The logotype extension must not be marked critical.");
        }

        /*        
        LogotypeExtn ::= SEQUENCE {
            communityLogos  [0] EXPLICIT SEQUENCE OF LogotypeInfo OPTIONAL,
            issuerLogo      [1] EXPLICIT LogotypeInfo OPTIONAL,
            subjectLogo     [2] EXPLICIT LogotypeInfo OPTIONAL,
            otherLogos      [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL }
        */                                

        $communityLogos = [];
        $issuerLogo = null;
        $subjectLogo = null;
        $otherLogos = [];

        
        $seq = UnspecifiedType::fromDER($data)->asSequence(); 

        if ($seq->count() == 0) {
            throw new LogicException("At least one logo must be present.");    
        }

        if ($seq->hasTagged(0)) {
            $communityLogos = array_map(
                function (UnspecifiedType $element) {
                    return LogotypeInfo::fromASN1($element->asTagged()->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
                }, $seq->getTagged(0)->asImplicit(Element::TYPE_SEQUENCE)->asSequence()->elements());
        }

        if ($seq->hasTagged(1)) {
            $issuerLogo = LogotypeInfo::fromASN1($seq->getTagged(1)->asImplicit(Element::TYPE_SEQUENCE)->asSequence());   
        }

        if ($seq->hasTagged(2)) {            
            $subjectLogo = LogotypeInfo::fromASN1($seq->getTagged(2)->asImplicit(Element::TYPE_SEQUENCE)->asSequence());   
        }

        if ($seq->hasTagged(3)) {
            $otherLogos = array_map(
                function (UnspecifiedType $element) {
                    return OtherLogotypeInfo::fromASN1($element->asTagged()->asImplicit(Element::TYPE_SEQUENCE)->asSequence());
                }, $seq->getTagged(3)->asImplicit(Element::TYPE_SEQUENCE)->asSequence()->elements());
            
        }        
        
        return new self($communityLogos, $issuerLogo, $subjectLogo, $otherLogos);
    }

}