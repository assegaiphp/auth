<?php

use Assegai\Auth\Exceptions\OAuthProviderException;
use Assegai\Auth\Exceptions\OAuthStateException;
use Assegai\Auth\Interfaces\OAuthProviderInterface;
use Assegai\Auth\Interfaces\OAuthStateStoreInterface;
use Assegai\Auth\OAuth\DefaultOAuthUserResolver;
use Assegai\Auth\OAuth\OAuth2AuthStrategy;
use Assegai\Auth\OAuth\OAuthProviderConfig;
use Assegai\Auth\OAuth\ValueObjects\OAuthTokenResponse;
use Assegai\Auth\OAuth\ValueObjects\OAuthUserProfile;
use Assegai\Auth\Strategies\JwtAuthStrategy;
use Assegai\Auth\Strategies\SessionAuthStrategy;

it('builds an authorization request and stores state', function () {
  $store = new class implements OAuthStateStoreInterface {
    public ?string $provider = null;
    public ?string $state = null;
    public ?string $verifier = null;

    public function store(string $provider, string $state, ?string $codeVerifier = null): void
    {
      $this->provider = $provider;
      $this->state = $state;
      $this->verifier = $codeVerifier;
    }

    public function consume(string $provider, string $state): ?string
    {
      return null;
    }
  };

  $provider = new class implements OAuthProviderInterface {
    public function getName(): string
    {
      return 'github';
    }

    public function buildAuthorizationUrl(OAuthProviderConfig $config, string $state, ?string $codeChallenge = null, string $codeChallengeMethod = 'S256'): string
    {
      return 'https://example.test/authorize?state=' . urlencode($state) . '&challenge=' . urlencode((string) $codeChallenge);
    }

    public function exchangeCode(OAuthProviderConfig $config, string $code, ?string $codeVerifier = null): OAuthTokenResponse
    {
      throw new RuntimeException('Not used in this test.');
    }

    public function fetchUserProfile(OAuthProviderConfig $config, OAuthTokenResponse $tokens): OAuthUserProfile
    {
      throw new RuntimeException('Not used in this test.');
    }
  };

  $strategy = new OAuth2AuthStrategy(
    provider: $provider,
    config: new OAuthProviderConfig('id', 'secret', 'https://app/callback', 'https://auth', 'https://token', 'https://user'),
    stateStore: $store,
  );

  $request = $strategy->beginLogin();

  expect($request->url)->toContain('https://example.test/authorize')
    ->and($request->state)->toBeString()->not->toBeEmpty()
    ->and($request->codeVerifier)->toBeString()->not->toBeEmpty()
    ->and($store->provider)->toBe('github')
    ->and($store->state)->toBe($request->state)
    ->and($store->verifier)->toBe($request->codeVerifier);
});

it('can handle a callback and establish session and jwt auth', function () {
  if (session_status() === PHP_SESSION_ACTIVE) {
    $_SESSION = [];
    session_destroy();
  }

  $stateStore = new class implements OAuthStateStoreInterface {
    public function store(string $provider, string $state, ?string $codeVerifier = null): void
    {
    }

    public function consume(string $provider, string $state): ?string
    {
      return 'pkce-verifier';
    }
  };

  $provider = new class implements OAuthProviderInterface {
    public function getName(): string
    {
      return 'github';
    }

    public function buildAuthorizationUrl(OAuthProviderConfig $config, string $state, ?string $codeChallenge = null, string $codeChallengeMethod = 'S256'): string
    {
      return 'https://example.test/authorize';
    }

    public function exchangeCode(OAuthProviderConfig $config, string $code, ?string $codeVerifier = null): OAuthTokenResponse
    {
      expect($code)->toBe('callback-code')
        ->and($codeVerifier)->toBe('pkce-verifier');

      return new OAuthTokenResponse('access-token');
    }

    public function fetchUserProfile(OAuthProviderConfig $config, OAuthTokenResponse $tokens): OAuthUserProfile
    {
      return new OAuthUserProfile(
        provider: 'github',
        providerId: '123',
        email: 'oauth@example.com',
        name: 'OAuth User',
        username: 'oauth-user',
      );
    }
  };

  $sessionStrategy = new SessionAuthStrategy(['user' => (object) []]);
  $jwtStrategy = new JwtAuthStrategy([
    'secret_key' => 'replace-with-a-long-random-secret-key',
    'user' => (object) [
      'email' => 'placeholder@example.com',
      'password' => password_hash('placeholder', PASSWORD_DEFAULT),
    ],
  ]);

  $strategy = new OAuth2AuthStrategy(
    provider: $provider,
    config: new OAuthProviderConfig('id', 'secret', 'https://app/callback', 'https://auth', 'https://token', 'https://user'),
    stateStore: $stateStore,
    userResolver: new DefaultOAuthUserResolver(),
    sessionStrategy: $sessionStrategy,
    jwtStrategy: $jwtStrategy,
  );

  $result = $strategy->handleCallback([
    'code' => 'callback-code',
    'state' => 'state-123',
  ]);

  expect($result->sessionEstablished)->toBeTrue()
    ->and($result->jwtToken)->toBeString()->not->toBeEmpty()
    ->and($result->user)->toHaveProperty('email', 'oauth@example.com')
    ->and($sessionStrategy->getUser())->toHaveProperty('email', 'oauth@example.com');
});

it('rejects invalid callback state', function () {
  $strategy = new OAuth2AuthStrategy(
    provider: new class implements OAuthProviderInterface {
      public function getName(): string
      {
        return 'github';
      }

      public function buildAuthorizationUrl(OAuthProviderConfig $config, string $state, ?string $codeChallenge = null, string $codeChallengeMethod = 'S256'): string
      {
        return '';
      }

      public function exchangeCode(OAuthProviderConfig $config, string $code, ?string $codeVerifier = null): OAuthTokenResponse
      {
        throw new RuntimeException('Not used.');
      }

      public function fetchUserProfile(OAuthProviderConfig $config, OAuthTokenResponse $tokens): OAuthUserProfile
      {
        throw new RuntimeException('Not used.');
      }
    },
    config: new OAuthProviderConfig('id', 'secret', 'https://app/callback', 'https://auth', 'https://token', 'https://user'),
    stateStore: new class implements OAuthStateStoreInterface {
      public function store(string $provider, string $state, ?string $codeVerifier = null): void
      {
      }

      public function consume(string $provider, string $state): ?string
      {
        return null;
      }
    },
  );

  expect(fn () => $strategy->handleCallback([
    'code' => 'callback-code',
    'state' => 'wrong-state',
  ]))->toThrow(OAuthStateException::class);
});

it('surfaces provider callback errors cleanly', function () {
  $strategy = new OAuth2AuthStrategy(
    provider: new class implements OAuthProviderInterface {
      public function getName(): string
      {
        return 'github';
      }

      public function buildAuthorizationUrl(OAuthProviderConfig $config, string $state, ?string $codeChallenge = null, string $codeChallengeMethod = 'S256'): string
      {
        return '';
      }

      public function exchangeCode(OAuthProviderConfig $config, string $code, ?string $codeVerifier = null): OAuthTokenResponse
      {
        throw new RuntimeException('Not used.');
      }

      public function fetchUserProfile(OAuthProviderConfig $config, OAuthTokenResponse $tokens): OAuthUserProfile
      {
        throw new RuntimeException('Not used.');
      }
    },
    config: new OAuthProviderConfig('id', 'secret', 'https://app/callback', 'https://auth', 'https://token', 'https://user'),
    stateStore: new class implements OAuthStateStoreInterface {
      public function store(string $provider, string $state, ?string $codeVerifier = null): void
      {
      }

      public function consume(string $provider, string $state): ?string
      {
        return 'verifier';
      }
    },
  );

  expect(fn () => $strategy->handleCallback([
    'error' => 'access_denied',
  ]))->toThrow(OAuthProviderException::class);
});
