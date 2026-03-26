<?php

namespace Assegai\Auth\OAuth\Providers;

use Assegai\Auth\Exceptions\OAuthProviderException;
use Assegai\Auth\OAuth\OAuthProviderConfig;
use Assegai\Auth\OAuth\ValueObjects\OAuthTokenResponse;
use Assegai\Auth\OAuth\ValueObjects\OAuthUserProfile;

class GitHubOAuthProvider extends AbstractOAuthProvider
{
  public function getName(): string
  {
    return 'github';
  }

  public function fetchUserProfile(
    OAuthProviderConfig $config,
    OAuthTokenResponse $tokens,
  ): OAuthUserProfile
  {
    $profile = $this->getJson(
      $config->userInfoEndpoint,
      [
        'Accept: application/json',
        'Authorization: Bearer ' . $tokens->accessToken,
        'User-Agent: Assegai-Auth',
      ]
    );

    if (!array_key_exists('id', $profile)) {
      throw new OAuthProviderException('GitHub user profile did not include an id.');
    }

    return new OAuthUserProfile(
      provider: $this->getName(),
      providerId: (string) $profile['id'],
      email: isset($profile['email']) && is_string($profile['email']) ? $profile['email'] : null,
      name: isset($profile['name']) && is_string($profile['name']) ? $profile['name'] : null,
      username: isset($profile['login']) && is_string($profile['login']) ? $profile['login'] : null,
      avatarUrl: isset($profile['avatar_url']) && is_string($profile['avatar_url']) ? $profile['avatar_url'] : null,
      raw: $profile,
    );
  }

  public static function defaultConfig(
    string $clientId,
    string $clientSecret,
    string $redirectUri,
    array $scopes = ['read:user', 'user:email'],
  ): OAuthProviderConfig
  {
    return new OAuthProviderConfig(
      clientId: $clientId,
      clientSecret: $clientSecret,
      redirectUri: $redirectUri,
      authorizationEndpoint: 'https://github.com/login/oauth/authorize',
      tokenEndpoint: 'https://github.com/login/oauth/access_token',
      userInfoEndpoint: 'https://api.github.com/user',
      scopes: $scopes,
    );
  }
}
