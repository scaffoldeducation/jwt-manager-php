

# Jwt Manager PHP

PHP library to manage JWT authentication

### Installation

Requires [PHP](https://php.net) 7.1.

- Original source and doc: [Kiwfy - JWT Manager PHP](https://github.com/kiwfy/jwt-manager-php) 

The recommended way to install is through [Composer](https://getcomposer.org/).

```sh
composer require scaffoldeducation/jwt-manager-php
```
### Migration

To execute migration on a Lumen system, you will need import JwtManagerServiceProvider in you application:

Open ```.\bootstrap\app.php``` and add this line:
```$app->register(JwtManager\JwtManagerServiceProvider::class);```

You can custom blacklist table name at your .env file (```default: oauth_jwt_blacklist```):

```OAUTH_TABLE_BLACKLIST=oauth_jwt_blacklist```

Now execute on your terminal this command: ```php artisan migratre```

### Usage

Import this library in your application and use:

```php
// expire and renew is seconds (900 = 15 minutes)
$jwt = new JwtManager(string $appSecret, string $context, int $expire, int $renew);

// generete a new token
$token = $jwt->generate(string $audience, string $subject, array $payload);

// to invalid this token, use:
$jwt->turnInvalid($token);
```

### Sample

it's a good idea to look in the sample folder to understand how it works.

First verify if all dependencies is installed (if need anyelse)
```sh
composer install --no-dev --prefer-dist
```

and run
```sh
php sample/jwtManager-sample.php
```