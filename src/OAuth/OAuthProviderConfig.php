<?php

namespace Assegai\Auth\OAuth;

readonly class OAuthProviderConfig
{
  /**
   * @param array<int, string> $scopes
   * @param array<string, scalar|array|null> $extra
   */
  public function __construct(
    public string $clientId,
    public string $clientSecret,
    public string $redirectUri,
    public string $authorizationEndpoint,
    public string $tokenEndpoint,
    public string $userInfoEndpoint,
    public array $scopes = [],
    public array $extra = [],
  )
  {
  }
}
