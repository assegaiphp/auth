<?php

namespace Assegai\Auth\Strategies;

use Assegai\Auth\Exceptions\AuthException;
use Assegai\Auth\Interfaces\AuthStrategyInterface;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * A JWT authentication strategy.
 *
 * @package Assegai\Auth\Strategies
 */
class JwtAuthStrategy implements AuthStrategyInterface
{
  /**
   * @var object|null The authenticated user.
   */
  protected ?object $user = null;
  /**
   * @var string The JWT token.
   */
  protected string $token = '';

  /**
   * Constructs a JwtAuthStrategy.
   *
   * @param object $userData The user data.
   * @param string $secretKey The secret key.
   * @param string $audience The audience.
   * @param string $issuer The issuer.
   * @param string $authUsernameField The username field.
   * @param string $authPasswordField The password field.
   * @param string $lifetime The token lifetime.
   */
  public function __construct(
    protected object $userData,
    protected string $secretKey,
    protected string $audience,
    protected string $issuer,
    protected string $authUsernameField = 'email',
    protected string $authPasswordField = 'password',
    protected string $lifetime = '1 hour',
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
      !property_exists($this->userData, $usernameField) ||
      !property_exists($this->userData, $passwordField)
    ) {
      throw new AuthException('Invalid user data.');
    }

    if (
      !key_exists($usernameField, $credentials) ||
      !key_exists($passwordField, $credentials)
    ) {
      throw new AuthException('Invalid credentials.');
    }

    if ($credentials[$usernameField] !== $this->userData->$usernameField) {
      return false;
    }

    if (!password_verify($credentials[$passwordField], $this->userData->$passwordField)) {
      return false;
    }

    // Generate JWT token.
    $payload = [
      'sub' => $this->userData->id ?? $this->userData->$usernameField,
      $usernameField => $this->userData->$usernameField,
      'iat' => time(),
      'exp' => strtotime($this->lifetime ?? '1 hour'),
    ];

    if (isset($this->userData->roles)) {
      $payload['roles'] = $this->userData->roles;
    }

    if (isset($this->userData->name)) {
      $payload['name'] = $this->userData->name;
    }

    if (isset($this->userData->firstName) && isset($this->userData->lastName)) {
      $payload['name'] = "{$this->userData->firstName} {$this->userData->lastName}";
    }

    $this->token = JWT::encode($payload, $this->secretKey, 'HS256');
    $this->user = (object)$payload;

    return true;
  }

  /**
   * @inheritDoc
   */
  public function isAuthenticated(): bool
  {
    if (!isset($_SERVER['HTTP_AUTHORIZATION'])) {
      return false;
    }

    $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
    try {
      $decoded = JWT::decode($token, new Key($this->secretKey, 'HS256'));
      $this->user = $decoded;
    } catch (Exception) {
      return false;
    }

    return true;
  }

  /**
   * @inheritDoc
   */
  public function getUser(): ?object
  {
    return $this->user;
  }

  /**
   * @inheritDoc
   */
  public function logout(): void
  {
    $this->user = null;
  }

  /**
   * Get the JWT token.
   *
   * @return string The JWT token.
   */
  public function getToken(): string
  {
    return $this->token;
  }
}