<?php

namespace Assegaiphp\Auth\Interfaces;

interface AuthStrategyInterface
{
  /**
   * Authenticate a user based on the provided credentials.
   *
   * @param array $credentials User credentials (e.g., username, password, token).
   * @return bool True if authentication succeeds, false otherwise.
   */
  public function authenticate(array $credentials): bool;

  /**
   * Check if the user is authenticated.
   *
   * @return bool True if the user is authenticated, false otherwise.
   */
  public function isAuthenticated(): bool;

  /**
   * Get the authenticated user's data.
   *
   * @return array|null The authenticated user's data, or null if not authenticated.
   */
  public function getUser(): ?array;

  /**
   * Log out the user.
   *
   * @return void
   */
  public function logout(): void;
}