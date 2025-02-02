<?php

use Assegai\Auth\Exceptions\MalformedCredentialsException;
use Assegai\Auth\Strategies\JwtAuthStrategy;

beforeEach(function() {
  define('TEST_EMAIL', 'user@example.com');
  define('TEST_PASSWORD', 'password');
  define('JWT_SECRET', 'secret');

  $this->user = new stdClass();
  $this->user->email = TEST_EMAIL;
  $this->user->password = password_hash(TEST_PASSWORD, PASSWORD_DEFAULT);
});

it('can be instantiated', function() {
  try {
    expect(new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]))
      ->toBeInstanceOf(JwtAuthStrategy::class);
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can authenticate a user', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    expect($strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD]))
      ->toBeTrue();
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can generate a token', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    if (!$strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD])) {
      $this->fail('Failed to authenticate user');
    }
    expect($strategy->getToken())
      ->not()->toBeEmpty()
      ->toBeString()
      ->and(explode('.', $strategy->getToken()))
      ->toHaveCount(3);
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can validate a token', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    if (!$strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD])) {
      $this->fail('Failed to authenticate user');
    }
    expect($strategy->isAuthenticated())
      ->toBeTrue();
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can fail to authenticate a user with missing email', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    expect($strategy->authenticate(['password' => TEST_PASSWORD]))
      ->toBeFalse();
  } catch (Exception $exception) {
    expect($exception)
      ->toBeInstanceOf(MalformedCredentialsException::class);
  }
});

it('can fail to authenticate a user with missing password', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    expect($strategy->authenticate(['email' => TEST_EMAIL]))
      ->toBeFalse();
  } catch (Exception $exception) {
    expect($exception)
      ->toBeInstanceOf(MalformedCredentialsException::class);
  }
});

it('can check if a user is not authenticated', function() {
  try {
    $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer invalid_token';
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    expect($strategy->isAuthenticated())
      ->toBeFalse();
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can get the user', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    if (!$strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD])) {
      $this->fail('Failed to authenticate user');
    }
    expect($strategy->getUser())
      ->toBeObject()
      ->toHaveProperty('email', TEST_EMAIL)
      ->not()->toHaveProperty('password');
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can logout a user', function() {
  try {
    $strategy = new JwtAuthStrategy($this->user, ['secret_key' => JWT_SECRET]);
    if (!$strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD])) {
      $this->fail('Failed to authenticate user');
    }
    $strategy->logout();
    expect($strategy->isAuthenticated())
      ->toBeFalse();
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});