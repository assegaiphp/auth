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

    $this->establishAuthenticatedUser($this->user);
    return true;
  }

  /**
   * Establishes a trusted authenticated user without re-validating credentials.
   *
   * @param object $user
   * @return void
   * @throws AuthException
   */
  public function establishAuthenticatedUser(object $user): void
  {
    $this->ensureSessionStarted();
    $this->rotateSessionIdentifier();
    $_SESSION[self::SESSION_USER_FIELD] = $this->sanitizeUser($user);
  }

  /**
   * @inheritDoc
   */
  public function isAuthenticated(): bool
  {
    $this->ensureSessionStarted();
    return isset($_SESSION[self::SESSION_USER_FIELD]);
  }

  /**
   * @inheritDoc
   */
  public function getUser(): ?object
  {
    $this->ensureSessionStarted();
    return $_SESSION[self::SESSION_USER_FIELD] ?? null;
  }

  /**
   * @inheritDoc
   */
  public function logout(): void
  {
    if (session_status() === PHP_SESSION_NONE) {
      $this->ensureSessionStarted();
    }

    $_SESSION = [];

    if (session_status() === PHP_SESSION_ACTIVE) {
      $params = session_get_cookie_params();

      if (session_name() !== '') {
        setcookie(
          session_name(),
          '',
          [
            'expires' => time() - 42000,
            'path' => $params['path'] ?? '/',
            'domain' => $params['domain'] ?? '',
            'secure' => (bool) ($params['secure'] ?? false),
            'httponly' => (bool) ($params['httponly'] ?? true),
            'samesite' => $params['samesite'] ?? 'Lax',
          ]
        );
      }

      session_destroy();
    }
  }

  /**
   * @throws AuthException
   */
  protected function ensureSessionStarted(): void
  {
    if (session_status() === PHP_SESSION_ACTIVE) {
      return;
    }

    if ($this->shouldUsePseudoSession()) {
      if (!isset($_SESSION) || !is_array($_SESSION)) {
        $_SESSION = [];
      }

      return;
    }

    $this->prepareSessionStorage();

    $useCookies = $this->shouldUseSessionCookies();

    if ($this->sessionName && session_name() !== $this->sessionName) {
      if (false === session_name($this->sessionName)) {
        throw new AuthException('Failed to set session name.');
      }
    }

    $cookieLifetime = $this->resolveSessionLifetime();

    if ($useCookies && $cookieLifetime !== null) {
      $params = session_get_cookie_params();

      if (false === session_set_cookie_params([
        'lifetime' => $cookieLifetime,
        'path' => $params['path'] ?? '/',
        'domain' => $params['domain'] ?? '',
        'secure' => (bool) ($params['secure'] ?? false),
        'httponly' => (bool) ($params['httponly'] ?? true),
        'samesite' => $params['samesite'] ?? 'Lax',
      ])) {
        throw new AuthException('Failed to set session lifetime.');
      }
    }

    $sessionOptions = [];

    if (!$useCookies) {
      $sessionOptions = [
        'use_cookies' => 0,
        'cache_limiter' => '',
      ];
    }

    if (false === session_start($sessionOptions)) {
      throw new AuthException('Failed to start the session.');
    }
  }

  /**
   * @throws AuthException
   */
  protected function rotateSessionIdentifier(): void
  {
    if ($this->shouldUsePseudoSession() || session_status() !== PHP_SESSION_ACTIVE) {
      return;
    }

    if (false === session_regenerate_id(true)) {
      throw new AuthException('Failed to rotate the session identifier.');
    }
  }

  protected function sanitizeUser(object $user): object
  {
    $sanitized = clone $user;
    $passwordField = $this->passwordField;

    if (property_exists($sanitized, $passwordField)) {
      unset($sanitized->$passwordField);
    }

    return $sanitized;
  }

  protected function resolveSessionLifetime(): ?int
  {
    if ($this->sessionLifetime === null || $this->sessionLifetime === '') {
      return null;
    }

    if (is_int($this->sessionLifetime)) {
      return max(0, $this->sessionLifetime);
    }

    $timestamp = strtotime($this->sessionLifetime, time());

    if ($timestamp === false) {
      throw new AuthException('Invalid session lifetime value.');
    }

    return max(0, $timestamp - time());
  }

  protected function shouldUseSessionCookies(): bool
  {
    return PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg' && !headers_sent();
  }

  protected function shouldUsePseudoSession(): bool
  {
    return (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') && headers_sent();
  }

  /**
   * @throws AuthException
   */
  protected function prepareSessionStorage(): void
  {
    if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
      return;
    }

    if (session_module_name() !== 'files') {
      return;
    }

    $savePath = sys_get_temp_dir() . '/assegaiphp-auth-sessions';

    if (!is_dir($savePath) && !mkdir($savePath, 0777, true) && !is_dir($savePath)) {
      throw new AuthException('Failed to prepare the session storage directory.');
    }

    if (false === session_save_path($savePath)) {
      throw new AuthException('Failed to configure the session storage directory.');
    }
  }
}
