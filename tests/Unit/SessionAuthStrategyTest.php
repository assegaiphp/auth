<?php

use Assegai\Auth\Exceptions\MalformedCredentialsException;
use Assegai\Auth\Strategies\SessionAuthStrategy;

beforeEach(function() {
  define('TEST_EMAIL', 'user@example.com');
  define('TEST_PASSWORD', 'password');

  $this->user = new stdClass();
  $this->user->email = TEST_EMAIL;
  $this->user->password = password_hash(TEST_PASSWORD, PASSWORD_DEFAULT);
});

it('can be instantiated', function () {
    expect(new SessionAuthStrategy(['user' => $this->user]))
      ->toBeInstanceOf(SessionAuthStrategy::class);
});

it('can authenticate a user', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    expect($strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD]))
      ->toBeTrue();
  } catch (Exception) {
    $this->fail('Authentication test failed');
  }
});

it('can fail to authenticate a user', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    expect($strategy->authenticate(['email' => TEST_EMAIL, 'password' => 'wrongpassword']))
      ->toBeFalse();
  } catch (Exception) {
    $this->fail('Authentication test failed');
  }
});

it('can fail to authenticate a user with missing email', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate(['password' => TEST_PASSWORD]);
  } catch (Exception $exception) {
    expect($exception)->toBeInstanceOf(MalformedCredentialsException::class);
  }
});

it('can fail to authenticate a user with missing password', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate(['email' => TEST_EMAIL]);
  } catch (Exception $exception) {
    expect($exception)->toBeInstanceOf(MalformedCredentialsException::class);
  }
});

it('can fail to authenticate a user with missing email and password', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate([]);
  } catch (Exception $exception) {
    expect($exception)->toBeInstanceOf(MalformedCredentialsException::class);
  }
});

it('can check if a user is authenticated', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD]);
    expect($strategy->isAuthenticated())->toBeTrue();
  } catch (Exception) {
    $this->fail('Authentication test failed');
  }
});

it('can check if a user is not authenticated', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);
  $_SESSION = [];

  try {
    $strategy->authenticate(['email' => TEST_EMAIL, 'password' => 'wrongpassword']);
    expect($strategy->isAuthenticated())->toBeFalse();
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can get the user', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD]);
    $expectedUser = clone $this->user;
    unset($expectedUser->password);
    expect($strategy->getUser())->toEqual($expectedUser);
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can get the user with password removed', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD]);
    expect($strategy->getUser())
      ->not()
      ->toHaveKey('password')
      ->and($this->user)
      ->toHaveKey('password');
  } catch (Exception $exception) {
    $this->fail($exception->getMessage());
  }
});

it('can logout a user', function () {
  $strategy = new SessionAuthStrategy(['user' => $this->user]);

  try {
    $strategy->authenticate(['email' => TEST_EMAIL, 'password' => TEST_PASSWORD]);
    $strategy->logout();
    expect($strategy->isAuthenticated())->toBeFalse();
  } catch (Exception) {
    $this->fail('Authentication test failed');
  }
});