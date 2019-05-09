<?php

declare(strict_types = 1);

namespace Sop\X509\Certificate\Extension\AccessDescription;

/**
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.2
 */
class SubjectAccessDescription extends AccessDescription
{
    /**
     * Access method OID's.
     *
     * @var string
     */
    const OID_METHOD_TIME_STAMPING = '1.3.6.1.5.5.7.48.3';
    const OID_METHOD_CA_REPOSITORY = '1.3.6.1.5.5.7.48.5';

    /**
     * Check whether access method is time stamping.
     *
     * @return bool
     */
    public function isTimeStampingMethod(): bool
    {
        return self::OID_METHOD_TIME_STAMPING === $this->_accessMethod;
    }

    /**
     * Check whether access method is CA repository.
     *
     * @return bool
     */
    public function isCARepositoryMethod(): bool
    {
        return self::OID_METHOD_CA_REPOSITORY === $this->_accessMethod;
    }
}
