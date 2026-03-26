<?php

namespace Assegai\Auth\OAuth\ValueObjects;

readonly class OAuthAuthorizationRequest
{
  public function __construct(
    public string $url,
    public string $state,
    public ?string $codeVerifier = null,
    public ?string $codeChallenge = null,
    public string $codeChallengeMethod = 'S256',
  )
  {
  }
}
