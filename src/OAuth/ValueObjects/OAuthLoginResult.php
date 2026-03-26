<?php

namespace Assegai\Auth\OAuth\ValueObjects;

readonly class OAuthLoginResult
{
  public function __construct(
    public object $user,
    public OAuthUserProfile $profile,
    public OAuthTokenResponse $tokens,
    public bool $sessionEstablished = false,
    public ?string $jwtToken = null,
  )
  {
  }
}
