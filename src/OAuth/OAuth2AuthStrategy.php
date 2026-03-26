<?php

namespace Assegai\Auth\OAuth;

use Assegai\Auth\Exceptions\OAuthException;
use Assegai\Auth\Exceptions\OAuthProviderException;
use Assegai\Auth\Exceptions\OAuthStateException;
use Assegai\Auth\Interfaces\OAuthProviderInterface;
use Assegai\Auth\Interfaces\OAuthStateStoreInterface;
use Assegai\Auth\Interfaces\OAuthUserResolverInterface;
use Assegai\Auth\OAuth\Support\Pkce;
use Assegai\Auth\OAuth\ValueObjects\OAuthAuthorizationRequest;
use Assegai\Auth\OAuth\ValueObjects\OAuthLoginResult;
use Assegai\Auth\Strategies\JwtAuthStrategy;
use Assegai\Auth\Strategies\SessionAuthStrategy;

class OAuth2AuthStrategy
{
  public function __construct(
    private readonly OAuthProviderInterface $provider,
    private readonly OAuthProviderConfig $config,
    private readonly OAuthStateStoreInterface $stateStore,
    private readonly OAuthUserResolverInterface $userResolver = new DefaultOAuthUserResolver(),
    private readonly ?SessionAuthStrategy $sessionStrategy = null,
    private readonly ?JwtAuthStrategy $jwtStrategy = null,
    private readonly bool $usePkce = true,
  )
  {
  }

  public function beginLogin(): OAuthAuthorizationRequest
  {
    $state = $this->generateState();
    $codeVerifier = null;
    $codeChallenge = null;

    if ($this->usePkce) {
      $codeVerifier = Pkce::generateVerifier();
      $codeChallenge = Pkce::createS256Challenge($codeVerifier);
    }

    $this->stateStore->store($this->provider->getName(), $state, $codeVerifier);

    return new OAuthAuthorizationRequest(
      url: $this->provider->buildAuthorizationUrl($this->config, $state, $codeChallenge),
      state: $state,
      codeVerifier: $codeVerifier,
      codeChallenge: $codeChallenge,
    );
  }

  /**
   * @param array<string, mixed> $callback
   */
  public function handleCallback(array $callback): OAuthLoginResult
  {
    if (isset($callback['error']) && is_string($callback['error']) && $callback['error'] !== '') {
      throw new OAuthProviderException('OAuth provider returned an error: ' . $callback['error']);
    }

    $code = $callback['code'] ?? null;
    $state = $callback['state'] ?? null;

    if (!is_string($code) || $code === '') {
      throw new OAuthException('OAuth callback is missing the authorization code.');
    }

    if (!is_string($state) || $state === '') {
      throw new OAuthStateException('OAuth callback is missing the state value.');
    }

    $codeVerifier = $this->stateStore->consume($this->provider->getName(), $state);

    if ($this->usePkce && $codeVerifier === null) {
      throw new OAuthStateException('Invalid or expired OAuth state.');
    }

    if (!$this->usePkce && $codeVerifier === null) {
      throw new OAuthStateException('Invalid or expired OAuth state.');
    }

    $tokens = $this->provider->exchangeCode($this->config, $code, $codeVerifier);
    $profile = $this->provider->fetchUserProfile($this->config, $tokens);
    $user = $this->userResolver->resolve($profile, $tokens);

    $sessionEstablished = false;
    $jwtToken = null;

    if ($this->sessionStrategy instanceof SessionAuthStrategy) {
      $this->sessionStrategy->establishAuthenticatedUser($user);
      $sessionEstablished = true;
    }

    if ($this->jwtStrategy instanceof JwtAuthStrategy) {
      $jwtToken = $this->jwtStrategy->issueTokenForUser($user);
    }

    return new OAuthLoginResult(
      user: $user,
      profile: $profile,
      tokens: $tokens,
      sessionEstablished: $sessionEstablished,
      jwtToken: $jwtToken,
    );
  }

  protected function generateState(): string
  {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
  }
}
