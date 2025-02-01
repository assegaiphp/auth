<div align="center" style="padding-bottom: 48px">
    <a href="https://assegaiphp.com/" target="blank"><img src="https://assegaiphp.com/images/logos/logo-cropped.png" width="200" alt="Assegai Logo"></a>
</div>

<p style="text-align: center">A progressive <a href="https://php.net">PHP</a> framework for building effecient and scalable server-side applications.</p>

## Description

The Assegai Auth library provides authentication and authorization services. The library is built around an AuthStrategy interface that allows for the implementation of different authentication strategies. The library also provides a default strategy that uses JWT tokens for authentication.

This PHP library provides a flexible and modular way to implement various authentication strategies in your custom web framework. It includes support for session-based authentication, token-based authentication (JWT), OAuth 2.0, and more. The library is designed to be extensible, allowing you to easily add new authentication methods as needed.

---

## Installation
You can install the library via Composer:

```bash
composer require assegaiphp/auth
```

---

## Usage

### Basic Example
Here's a quick example of how to use the library with the session-based authentication strategy:

```php
<?php

require 'vendor/autoload.php';

use Assegai\Auth\Interfaces\SessionAuthStrategy;

// Get user object from Data Source e.g. Database
$user = (object)[
  'email' => 'user@example.com',
  'password' => '...', // Hashed password
];

$authStrategy = new SessionAuthStrategy($user);

if ($authStrategy->authenticate(['email' => 'user@example.com', 'password' => 'password'])) {
    echo "Authenticated! User: " . print_r($authStrategy->getUser(), true);
} else {
    echo "Authentication failed!";
}
```

### Switching Strategies
You can easily switch between different authentication strategies:

```php
<?php

use Assegai\Auth\SessionAuthStrategy;
use Assegai\Auth\JwtAuthStrategy;

// Get user object from Data Source e.g. Database
$user = (object)[
  'email' => 'user@example.com',
  'password' => '...', // Hashed password
];
$secretKey = 'your-secret-key';
$audience = 'your-audience';
$issuer = 'your-issuer';

// Use session-based authentication
$authStrategy = new SessionAuthStrategy($user);

// Or use JWT-based authentication
$authStrategy = new JwtAuthStrategy($user, ['secret_key' => $secretKey, 'audience' => $audience, 'issuer' => $issuer]);
```

---

## Available Strategies
The library currently supports the following authentication strategies:

1. **Session-Based Authentication**
    - Stores user data in server-side sessions.
    - Ideal for traditional web applications.

2. **Token-Based Authentication (JWT)**
    - Uses JSON Web Tokens (JWT) for stateless authentication.
    - Suitable for APIs and single-page applications (SPAs).

## Future Strategies
1. **OAuth 2.0**
    - Integrates with third-party OAuth providers (e.g., Google, Facebook).
    - Enables single sign-on (SSO) and social login.

2. **API Key Authentication**
    - Authenticates clients using API keys.
    - Designed for machine-to-machine (M2M) communication.

3. **Passwordless Authentication**
    - Authenticates users using magic links or one-time codes.
    - Eliminates the need for passwords.

---

## Configuration
Each authentication strategy can be configured to suit your application's needs. Below are examples of configuration options:

### Session-Based Authentication
```php
$authStrategy = new SessionAuthStrategy([
    'session_name' => 'my_app_session',
    'session_lifetime' => 3600, // 1 hour
]);
```

### JWT-Based Authentication
```php
$authStrategy = new JwtAuthStrategy([
    'secret_key' => 'your-secret-key',
    'algorithm' => 'HS256',
    'token_lifetime' => 3600, // 1 hour
]);
```

### OAuth 2.0
```php
$authStrategy = new OAuthAuthStrategy([
    'client_id' => 'your-client-id',
    'client_secret' => 'your-client-secret',
    'redirect_uri' => 'https://your-app.com/callback',
]);
```

---

## Advanced Usage

### Custom Strategies
You can create custom authentication strategies by implementing the `AuthStrategyInterface`:

```php
<?php

use Assegai\Auth\AuthStrategyInterface;

class CustomAuthStrategy implements AuthStrategyInterface
{
    public function authenticate(array $credentials): bool
    {
        // Implement custom authentication logic.
    }

    public function isAuthenticated(): bool
    {
        // Implement custom logic to check if the user is authenticated.
    }

    public function getUser(): ?array
    {
        // Implement custom logic to retrieve user data.
    }

    public function logout(): void
    {
        // Implement custom logout logic.
    }
}
```

### Middleware Integration
You can integrate the library with your framework's middleware system to protect routes:

```php
$app->addMiddleware(function ($request, $handler) use ($authStrategy) {
    if (!$authStrategy->isAuthenticated()) {
        return new Response('Unauthorized', 401);
    }
    return $handler->handle($request);
});
```

---

## API Reference

### `AuthStrategyInterface`

| Method | Description |
| --- | --- |
| `authenticate(array $credentials): bool` | Authenticates a user based on the provided credentials. |
| `isAuthenticated(): bool` | Checks if the user is authenticated. |
| `getUser(): ?array` | Returns the authenticated user's data. |
| `logout(): void` | Logs out the user. |

---

## Contributing
We welcome contributions! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

---

## License
This library is open-source and licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

## Support
If you encounter any issues or have questions, please open an issue on [GitHub](https://github.com/assegaiphp/auth/issues).

---

## Acknowledgments
- Thanks to the PHP community for their excellent tools and resources.
- Inspired by [Firebase JWT](https://github.com/firebase/php-jwt) and [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

---

This structure ensures that your `README.md` is comprehensive, user-friendly, and covers all the essential information for developers to get started with your library. Let me know if you'd like further refinements!