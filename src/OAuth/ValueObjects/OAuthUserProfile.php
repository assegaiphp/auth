<?php

namespace Assegai\Auth\OAuth\ValueObjects;

readonly class OAuthUserProfile
{
  /**
   * @param array<string, mixed> $raw
   */
  public function __construct(
    public string $provider,
    public string|int $providerId,
    public ?string $email = null,
    public ?string $name = null,
    public ?string $username = null,
    public ?string $avatarUrl = null,
    public array $raw = [],
  )
  {
  }
}
