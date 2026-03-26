<?php

namespace Assegai\Auth\OAuth\State;

use Assegai\Auth\Exceptions\OAuthException;
use Assegai\Auth\Interfaces\OAuthStateStoreInterface;

class SessionOAuthStateStore implements OAuthStateStoreInterface
{
  private const string SESSION_KEY = '__assegai_oauth_state';

  public function store(string $provider, string $state, ?string $codeVerifier = null): void
  {
    $this->ensureSessionStarted();

    if (!isset($_SESSION[self::SESSION_KEY]) || !is_array($_SESSION[self::SESSION_KEY])) {
      $_SESSION[self::SESSION_KEY] = [];
    }

    $_SESSION[self::SESSION_KEY][$provider] = [
      'state' => $state,
      'code_verifier' => $codeVerifier,
    ];
  }

  public function consume(string $provider, string $state): ?string
  {
    $this->ensureSessionStarted();

    $stored = $_SESSION[self::SESSION_KEY][$provider] ?? null;

    if (!is_array($stored) || ($stored['state'] ?? null) !== $state) {
      return null;
    }

    unset($_SESSION[self::SESSION_KEY][$provider]);

    return isset($stored['code_verifier']) && is_string($stored['code_verifier'])
      ? $stored['code_verifier']
      : null;
  }

  protected function ensureSessionStarted(): void
  {
    if (session_status() === PHP_SESSION_ACTIVE) {
      return;
    }

    if ($this->shouldUsePseudoSession()) {
      if (!isset($_SESSION) || !is_array($_SESSION)) {
        $_SESSION = [];
      }

      return;
    }

    $this->prepareSessionStorage();

    $sessionOptions = [];

    if (!$this->shouldUseSessionCookies()) {
      $sessionOptions = [
        'use_cookies' => 0,
        'cache_limiter' => '',
      ];
    }

    if (false === session_start($sessionOptions)) {
      throw new OAuthException('Failed to start the session for OAuth state handling.');
    }
  }

  protected function shouldUseSessionCookies(): bool
  {
    return PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg' && !headers_sent();
  }

  protected function shouldUsePseudoSession(): bool
  {
    return (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') && headers_sent();
  }

  /**
   * @throws OAuthException
   */
  protected function prepareSessionStorage(): void
  {
    if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
      return;
    }

    if (session_module_name() !== 'files') {
      return;
    }

    $savePath = sys_get_temp_dir() . '/assegaiphp-auth-sessions';

    if (!is_dir($savePath) && !mkdir($savePath, 0777, true) && !is_dir($savePath)) {
      throw new OAuthException('Failed to prepare the session storage directory.');
    }

    if (false === session_save_path($savePath)) {
      throw new OAuthException('Failed to configure the session storage directory.');
    }
  }
}
