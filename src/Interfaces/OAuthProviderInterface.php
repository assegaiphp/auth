<?php

namespace Assegai\Auth\Interfaces;

use Assegai\Auth\OAuth\OAuthProviderConfig;
use Assegai\Auth\OAuth\ValueObjects\OAuthTokenResponse;
use Assegai\Auth\OAuth\ValueObjects\OAuthUserProfile;

interface OAuthProviderInterface
{
  public function getName(): string;

  public function buildAuthorizationUrl(
    OAuthProviderConfig $config,
    string $state,
    ?string $codeChallenge = null,
    string $codeChallengeMethod = 'S256',
  ): string;

  public function exchangeCode(
    OAuthProviderConfig $config,
    string $code,
    ?string $codeVerifier = null,
  ): OAuthTokenResponse;

  public function fetchUserProfile(
    OAuthProviderConfig $config,
    OAuthTokenResponse $tokens,
  ): OAuthUserProfile;
}
