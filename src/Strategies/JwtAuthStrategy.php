<?php

namespace Assegai\Auth\Strategies;

use Assegai\Attributes\Injectable;
use Assegai\Auth\Exceptions\AuthException;
use Assegai\Auth\Exceptions\MalformedCredentialsException;
use Assegai\Auth\Interfaces\AuthStrategyInterface;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

/**
 * A JWT authentication strategy.
 *
 * @package Assegai\Auth\Strategies
 */
#[Injectable]
class JwtAuthStrategy implements AuthStrategyInterface
{
  /**
   * @var object The user data.
   */
  protected object $userData;
  /**
   * @var object|null The authenticated user.
   */
  protected ?object $user = null;
  /**
   * @var string The JWT token.
   */
  protected string $token = '';
  /**
   * @var string The secret key.
   */
  protected string $secretKey;
  /**
   * @var string The audience.
   */
  protected string $audience;
  /**
   * @var string The issuer.
   */
  protected string $issuer;
  /**
   * @var string The authentication username field.
   */
  protected string $authUsernameField = 'email';
  /**
   * @var string The authentication password field.
   */
  protected string $authPasswordField = 'password';
  /**
   * @var string|int|null The token lifetime.
   */
  protected string|int|null $tokenLifetime = '1 hour';
  /**
   * @var string The algorithm.
   */
  protected string $algorithm = 'HS256';

  /**
   * Constructs a JwtAuthStrategy.
   *
   * @param array{user: ?object, secret_key: ?string, algorithm: ?string, audience: ?string, issuer: ?string, username_field: ?string, password_field: ?string, token_lifetime: ?string, token: ?string} $config
   * @throws AuthException
   */
  public function __construct(
    array $config = []
  )
  {
    $this->userData = $config['user'] ?? new stdClass();
    $this->secretKey = $config['secret_key'] ?? throw new AuthException('Invalid secret key.');
    $this->algorithm = $config['algorithm'] ?? 'HS256';
    $this->audience = $config['audience'] ?? '';
    $this->issuer = $config['issuer'] ?? 'assegaiphp';
    $this->authUsernameField = $config['username_field'] ?? 'email';
    $this->authPasswordField = $config['password_field'] ?? 'password';
    $this->tokenLifetime = $config['token_lifetime'] ?? '1 hour';
    $this->token = $config['token'] ?? '';
  }

  /**
   * @inheritDoc
   */
  public function authenticate(array $credentials): bool
  {
    $usernameField = $this->authUsernameField;
    $passwordField = $this->authPasswordField;

    if (
      !is_object($this->user) ||
      !property_exists($this->userData, $usernameField) ||
      !property_exists($this->userData, $passwordField)
    ) {
      throw new AuthException('Invalid user data.');
    }

    if (
      !key_exists($usernameField, $credentials) ||
      !key_exists($passwordField, $credentials)
    ) {
      throw new MalformedCredentialsException();
    }

    if ($credentials[$usernameField] !== $this->userData->$usernameField) {
      return false;
    }

    if (!password_verify($credentials[$passwordField], $this->userData->$passwordField)) {
      return false;
    }

    // Generate JWT token.
    $lifetime = $this->tokenLifetime;

    if (!$lifetime) {
      $lifetime = '1 hour';
    }

    if (is_string($lifetime)) {
      $lifetime = strtotime($lifetime);
    }

    $payload = [
      'sub' => $this->userData->id ?? $this->userData->$usernameField,
      $usernameField => $this->userData->$usernameField,
      'iat' => time(),
      'exp' => $lifetime,
    ];

    if ($this->issuer) {
      $payload['iss'] = $this->issuer;
    }

    if ($this->audience) {
      $payload['aud'] = $this->audience;
    }

    if (isset($this->userData->roles)) {
      $payload['roles'] = $this->userData->roles;
    }

    if (isset($this->userData->name)) {
      $payload['name'] = $this->userData->name;
    }

    if (isset($this->userData->firstName) && isset($this->userData->lastName)) {
      $payload['name'] = "{$this->userData->firstName} {$this->userData->lastName}";
    }

    $this->token = JWT::encode($payload, $this->secretKey, $this->algorithm);
    $this->user = (object)$payload;

    return true;
  }

  /**
   * @inheritDoc
   */
  public function isAuthenticated(): bool
  {
    if (!isset($_SERVER['HTTP_AUTHORIZATION']) && !$this->token) {
      return false;
    }

    $token = $this->token;
    if (!$token) {
      $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
    }
    try {
      $decoded = JWT::decode($token, new Key($this->secretKey, $this->algorithm));
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

  /**
   * Get the decoded JWT token.
   *
   * @return stdClass The decoded JWT token.
   */
  public function getDecoded(): stdClass
  {
    return JWT::decode($this->token, new Key($this->secretKey, $this->algorithm));
  }
}