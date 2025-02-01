<?php

namespace Assegai\Auth\Strategies;

use Assegai\Auth\Exceptions\AuthException;
use Assegai\Auth\Interfaces\AuthStrategyInterface;

/**
 * A session-based authentication strategy.
 *
 * @package Assegaiphp\Auth\Strategies
 */
class SessionAuthStrategy implements AuthStrategyInterface
{
  const string SESSION_USER_FIELD = 'user';

  /**
   * Constructs a SessionAuthStrategy.
   *
   * @param object $user
   * @param string $authUsernameField
   * @param string $authPasswordField
   */
  public function __construct(
    protected object $user,
    protected string $authUsernameField = 'email',
    protected string $authPasswordField = 'password',
  )
  {
  }

  /**
   * @inheritDoc
   */
  public function authenticate(array $credentials): bool
  {
    $usernameField = $this->authUsernameField;
    $passwordField = $this->authPasswordField;

    if (
      !property_exists($this->user, $this->authUsernameField) ||
      !property_exists($this->user, $this->authPasswordField)
    ) {
      throw new AuthException('Invalid user object.');
    }

    if (
      !key_exists($usernameField, $credentials) ||
      !key_exists($passwordField, $credentials)
    ) {
      throw new AuthException('Invalid credentials.');
    }

    if ($credentials[$usernameField] !== $this->user->$usernameField) {
      return false;
    }

    if (!password_verify($credentials[$passwordField], $this->user->$passwordField)) {
      return false;
    }

    session_start();
    $_SESSION[self::SESSION_USER_FIELD] = $this->user;

    return true;
  }

  /**
   * @inheritDoc
   */
  public function isAuthenticated(): bool
  {
    session_start();
    return isset($_SESSION[self::SESSION_USER_FIELD]);
  }

  /**
   * @inheritDoc
   */
  public function getUser(): ?object
  {
    session_start();
    return $_SESSION[self::SESSION_USER_FIELD] ?? null;
  }

  /**
   * @inheritDoc
   */
  public function logout(): void
  {
    session_start();
    session_destroy();
  }
}