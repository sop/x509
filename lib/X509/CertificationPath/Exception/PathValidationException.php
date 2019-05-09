<?php

declare(strict_types = 1);

namespace Sop\X509\CertificationPath\Exception;

use Sop\X509\Exception\X509ValidationException;

/**
 * Exception thrown on certification path validation errors.
 */
class PathValidationException extends X509ValidationException
{
}
