<?php

namespace Assegai\Auth\OAuth;

use Assegai\Auth\Interfaces\OAuthUserResolverInterface;
use Assegai\Auth\OAuth\ValueObjects\OAuthTokenResponse;
use Assegai\Auth\OAuth\ValueObjects\OAuthUserProfile;

class DefaultOAuthUserResolver implements OAuthUserResolverInterface
{
  public function resolve(OAuthUserProfile $profile, OAuthTokenResponse $tokens): object
  {
    return (object) [
      'provider' => $profile->provider,
      'providerId' => $profile->providerId,
      'email' => $profile->email,
      'name' => $profile->name,
      'username' => $profile->username,
      'avatarUrl' => $profile->avatarUrl,
    ];
  }
}
