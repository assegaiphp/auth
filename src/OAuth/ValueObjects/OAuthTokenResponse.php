<?php

namespace Assegai\Auth\OAuth\ValueObjects;

readonly class OAuthTokenResponse
{
  /**
   * @param array<string, mixed> $raw
   */
  public function __construct(
    public string $accessToken,
    public ?string $refreshToken = null,
    public ?string $tokenType = null,
    public ?int $expiresIn = null,
    public ?string $scope = null,
    public array $raw = [],
  )
  {
  }
}
