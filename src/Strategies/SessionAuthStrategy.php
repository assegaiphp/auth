<?php

namespace Assegai\Auth\Strategies;

use Assegai\Attributes\Injectable;
use Assegai\Auth\Exceptions\AuthException;
use Assegai\Auth\Exceptions\MalformedCredentialsException;
use Assegai\Auth\Interfaces\AuthStrategyInterface;
use stdClass;

/**
 * A session-based authentication strategy.
 *
 * @package Assegaiphp\Auth\Strategies
 */
#[Injectable]
class SessionAuthStrategy implements AuthStrategyInterface
{
  /**
   * @var object The user data.
   */
  protected object $user;
  /**
   * The session user field.
   */
  const string SESSION_USER_FIELD = 'user';

  /**
   * @var string The username field.
   */
  protected string $usernameField = 'email';
  /**
   * @var string The password field.
   */
  protected string $passwordField = 'password';
  /**
   * @var string|null The session name.
   */
  protected ?string $sessionName = null;
  /**
   * @var string|int|null The session lifetime.
   */
  protected string|int|null $sessionLifetime = null;

  /**
   * Constructs a SessionAuthStrategy.
   *
   * @param array{user: ?object, session_name: ?string, session_lifetime: ?string, username_field: ?string, password_field: ?string} $config
   */
  public function __construct(
    array $config = []
  )
  {
    $this->user = $config['user'] ?? new stdClass();
    $this->sessionName = $config['session_name'] ?? null;
    $this->sessionLifetime = $config['session_lifetime'] ?? null;
    $this->usernameField = $config['username_field'] ?? $this->usernameField;
    $this->passwordField = $config['password_field'] ?? $this->passwordField;
  }

  /**
   * @inheritDoc
   * @throws AuthException
   */
  public function authenticate(array $credentials): bool
  {
    $usernameField = $this->usernameField;
    $passwordField = $this->passwordField;

    if (
      !is_object($this->user) ||
      !property_exists($this->user, $this->usernameField) ||
      !property_exists($this->user, $this->passwordField)
    ) {
      throw new AuthException('Invalid user object.');
    }

    if (
      !key_exists($usernameField, $credentials) ||
      !key_exists($passwordField, $credentials)
    ) {
      throw new MalformedCredentialsException();
    }

    if ($credentials[$usernameField] !== $this->user->$usernameField) {
      return false;
    }

    if (!password_verify($credentials[$passwordField], $this->user->$passwordField)) {
      return false;
    }

    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $user = clone $this->user;
    unset($user->$passwordField);
    $_SESSION[self::SESSION_USER_FIELD] = $user;
    if ($this->sessionName) {
      if ( false === session_name($this->sessionName) ) {
        throw new AuthException('Failed to set session name.');
      }
    }

    if ($this->sessionLifetime) {
      $lifetime = is_string($this->sessionLifetime) ? strtotime($this->sessionLifetime) : $this->sessionLifetime;
      if ( false === session_set_cookie_params($lifetime) ) {
        throw new AuthException('Failed to set session lifetime.');
      }
    }

    return true;
  }

  /**
   * @inheritDoc
   */
  public function isAuthenticated(): bool
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    return isset($_SESSION[self::SESSION_USER_FIELD]);
  }

  /**
   * @inheritDoc
   */
  public function getUser(): ?object
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    return $_SESSION[self::SESSION_USER_FIELD] ?? null;
  }

  /**
   * @inheritDoc
   */
  public function logout(): void
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    session_destroy();
  }
}