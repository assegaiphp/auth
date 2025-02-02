<?php

namespace Assegai\Auth\Exceptions;

use Exception;

/**
 * An exception that is thrown when an authentication error occurs.
 *
 * @package Assegaiphp\Auth\Exceptions
 */
class AuthException extends Exception
{
    /**
     * Constructs an AuthException.
     *
     * @param string $message The exception message.
     * @param int $code The exception code.
     * @param Exception|null $previous The previous exception.
     */
    public function __construct(string $message = 'Authentication error', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}