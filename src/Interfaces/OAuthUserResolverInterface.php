<?php

namespace Assegai\Auth\Interfaces;

use Assegai\Auth\OAuth\ValueObjects\OAuthTokenResponse;
use Assegai\Auth\OAuth\ValueObjects\OAuthUserProfile;

interface OAuthUserResolverInterface
{
  public function resolve(OAuthUserProfile $profile, OAuthTokenResponse $tokens): object;
}
