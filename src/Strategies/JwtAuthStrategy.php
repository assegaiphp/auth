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
    $this->assertSecretKeyStrength($this->secretKey);
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
      !is_object($this->userData) ||
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

    $this->issueTokenForUser($this->userData);
    return true;
  }

  /**
   * Issues a token for a trusted user object without re-validating credentials.
   *
   * @param object $user
   * @return string
   */
  public function issueTokenForUser(object $user): string
  {
    $payload = $this->buildPayload($user);
    $this->token = JWT::encode($payload, $this->secretKey, $this->algorithm);
    $this->user = (object) $payload;

    return $this->token;
  }

  /**
   * @inheritDoc
   */
  public function isAuthenticated(): bool
  {
    $token = $this->token ?: $this->resolveBearerToken();

    if (!$token) {
      return false;
    }

    try {
      $decoded = JWT::decode($token, new Key($this->secretKey, $this->algorithm));

      if (!$this->hasValidRegisteredClaims($decoded)) {
        return false;
      }

      $this->user = $decoded;
      $this->token = $token;
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
    $this->token = '';
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

  protected function buildPayload(object $user): array
  {
    $usernameField = $this->authUsernameField;
    $issuedAt = time();

    if (!property_exists($user, $usernameField)) {
      throw new AuthException("The user object must expose the configured username field '{$usernameField}'.");
    }

    $payload = [
      'sub' => $user->id ?? $user->$usernameField,
      $usernameField => $user->$usernameField,
      'iat' => $issuedAt,
      'exp' => $this->resolveTokenExpiry($issuedAt),
    ];

    if ($this->issuer) {
      $payload['iss'] = $this->issuer;
    }

    if ($this->audience) {
      $payload['aud'] = $this->audience;
    }

    if (isset($user->roles)) {
      $payload['roles'] = $user->roles;
    }

    if (isset($user->name)) {
      $payload['name'] = $user->name;
    }

    if (isset($user->firstName) && isset($user->lastName)) {
      $payload['name'] = "{$user->firstName} {$user->lastName}";
    }

    return $payload;
  }

  protected function resolveTokenExpiry(int $issuedAt): int
  {
    $lifetime = $this->tokenLifetime;

    if ($lifetime === null || $lifetime === '') {
      return $issuedAt + 3600;
    }

    if (is_int($lifetime)) {
      return $issuedAt + max(0, $lifetime);
    }

    $timestamp = strtotime($lifetime, $issuedAt);

    if ($timestamp === false) {
      throw new AuthException('Invalid token lifetime value.');
    }

    return $timestamp;
  }

  protected function hasValidRegisteredClaims(stdClass $decoded): bool
  {
    if ($this->issuer !== '' && (($decoded->iss ?? null) !== $this->issuer)) {
      return false;
    }

    if ($this->audience !== '' && !$this->audienceMatches($decoded->aud ?? null)) {
      return false;
    }

    return true;
  }

  protected function audienceMatches(mixed $audienceClaim): bool
  {
    if (is_string($audienceClaim)) {
      return $audienceClaim === $this->audience;
    }

    if (!is_array($audienceClaim)) {
      return false;
    }

    foreach ($audienceClaim as $candidate) {
      if (is_string($candidate) && $candidate === $this->audience) {
        return true;
      }
    }

    return false;
  }

  protected function resolveBearerToken(): ?string
  {
    $candidates = [
      $_SERVER['HTTP_AUTHORIZATION'] ?? null,
      $_SERVER['Authorization'] ?? null,
      $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null,
    ];

    if (function_exists('apache_request_headers')) {
      foreach ((array) apache_request_headers() as $name => $value) {
        if (strtolower((string) $name) === 'authorization') {
          $candidates[] = $value;
        }
      }
    }

    foreach ($candidates as $header) {
      if (!is_string($header) || $header === '') {
        continue;
      }

      if (preg_match('/^\s*Bearer\s+(.+)\s*$/i', $header, $matches) === 1) {
        return trim($matches[1]);
      }
    }

    return null;
  }

  protected function assertSecretKeyStrength(string $secretKey): void
  {
    if (str_starts_with($this->algorithm, 'HS') && strlen($secretKey) < 32) {
      throw new AuthException('Secret key must be at least 32 characters for HMAC algorithms.');
    }
  }
}
