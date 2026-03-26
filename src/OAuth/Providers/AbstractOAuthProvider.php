<?php

namespace Assegai\Auth\OAuth\Providers;

use Assegai\Auth\Exceptions\OAuthProviderException;
use Assegai\Auth\Interfaces\OAuthProviderInterface;
use Assegai\Auth\OAuth\OAuthProviderConfig;
use Assegai\Auth\OAuth\ValueObjects\OAuthTokenResponse;

abstract class AbstractOAuthProvider implements OAuthProviderInterface
{
  public function buildAuthorizationUrl(
    OAuthProviderConfig $config,
    string $state,
    ?string $codeChallenge = null,
    string $codeChallengeMethod = 'S256',
  ): string
  {
    $params = [
      'client_id' => $config->clientId,
      'redirect_uri' => $config->redirectUri,
      'response_type' => 'code',
      'state' => $state,
    ];

    if ($config->scopes !== []) {
      $params['scope'] = implode(' ', $config->scopes);
    }

    if ($codeChallenge !== null) {
      $params['code_challenge'] = $codeChallenge;
      $params['code_challenge_method'] = $codeChallengeMethod;
    }

    foreach ($config->extra as $key => $value) {
      if (is_scalar($value)) {
        $params[$key] = (string) $value;
      }
    }

    return $config->authorizationEndpoint . '?' . http_build_query($params);
  }

  public function exchangeCode(
    OAuthProviderConfig $config,
    string $code,
    ?string $codeVerifier = null,
  ): OAuthTokenResponse
  {
    $payload = [
      'grant_type' => 'authorization_code',
      'client_id' => $config->clientId,
      'client_secret' => $config->clientSecret,
      'redirect_uri' => $config->redirectUri,
      'code' => $code,
    ];

    if ($codeVerifier !== null) {
      $payload['code_verifier'] = $codeVerifier;
    }

    $response = $this->postForm($config->tokenEndpoint, $payload, [
      'Accept: application/json',
    ]);

    if (!isset($response['access_token']) || !is_string($response['access_token'])) {
      throw new OAuthProviderException('Provider token response did not include a valid access_token.');
    }

    return new OAuthTokenResponse(
      accessToken: $response['access_token'],
      refreshToken: isset($response['refresh_token']) && is_string($response['refresh_token']) ? $response['refresh_token'] : null,
      tokenType: isset($response['token_type']) && is_string($response['token_type']) ? $response['token_type'] : null,
      expiresIn: isset($response['expires_in']) ? (int) $response['expires_in'] : null,
      scope: isset($response['scope']) && is_string($response['scope']) ? $response['scope'] : null,
      raw: $response,
    );
  }

  /**
   * @param array<string, scalar|null> $payload
   * @param array<int, string> $headers
   * @return array<string, mixed>
   */
  protected function postForm(string $url, array $payload, array $headers = []): array
  {
    return $this->requestJson($url, [
      'method' => 'POST',
      'headers' => array_merge([
        'Content-Type: application/x-www-form-urlencoded',
      ], $headers),
      'body' => http_build_query(array_filter($payload, static fn(mixed $value): bool => $value !== null)),
    ]);
  }

  /**
   * @param array<int, string> $headers
   * @return array<string, mixed>
   */
  protected function getJson(string $url, array $headers = []): array
  {
    return $this->requestJson($url, [
      'method' => 'GET',
      'headers' => array_merge([
        'Accept: application/json',
      ], $headers),
    ]);
  }

  /**
   * @param array{method: string, headers?: array<int, string>, body?: string} $options
   * @return array<string, mixed>
   */
  protected function requestJson(string $url, array $options): array
  {
    $context = stream_context_create([
      'http' => [
        'method' => $options['method'],
        'ignore_errors' => true,
        'header' => implode("\r\n", $options['headers'] ?? []),
        'content' => $options['body'] ?? '',
      ],
    ]);

    $response = @file_get_contents($url, false, $context);

    if ($response === false) {
      throw new OAuthProviderException("Failed to contact OAuth provider at {$url}.");
    }

    $decoded = json_decode($response, true);

    if (!is_array($decoded)) {
      throw new OAuthProviderException('OAuth provider returned a non-JSON response.');
    }

    return $decoded;
  }
}
