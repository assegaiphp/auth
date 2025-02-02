<?php

namespace Assegai\Auth\Exceptions;

/**
 * Exception thrown when the credentials are malformed.
 *
 * @package Assegai\Auth\Exceptions
 */
class MalformedCredentialsException extends AuthException
{
  public function __construct()
  {
    parent::__construct('Malformed credentials', 400);
  }
}