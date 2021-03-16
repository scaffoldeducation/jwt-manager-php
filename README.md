
# Jwt Manager PHP

[![Latest Version](https://img.shields.io/github/v/release/kiwfy/jwt-manager-php.svg?style=flat-square)](https://github.com/kiwfy/jwt-manager-php/releases)
[![codecov](https://codecov.io/gh/kiwfy/jwt-manager-php/branch/master/graph/badge.svg)](https://codecov.io/gh/kiwfy/jwt-manager-php)
[![Build Status](https://img.shields.io/github/workflow/status/kiwfy/jwt-manager-php/CI?label=ci%20build&style=flat-square)](https://github.com/kiwfy/jwt-manager-php/actions?query=workflow%3ACI)
[![Total Downloads](https://img.shields.io/packagist/dt/kiwfy/jwt-manager-php.svg?style=flat-square)](https://packagist.org/packages/kiwfy/jwt-manager-php)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

PHP library to manage JWT authentication

### Installation

Requires [PHP](https://php.net) 7.1.

The recommended way to install is through [Composer](https://getcomposer.org/).

```sh
composer require scaffoldeducation/jwt-manager-php
```
### Migration

To execute migration on a Laravel or Lumen system, you will need import JwtManagerServiceProvider in you application:

**Lumen:**
Open ```\bootstrap\app.php``` and add this line:
```$app->register(JwtManager\JwtManagerServiceProvider::class);```

You can custom blacklist table name at your .env file (```default: oauth_jwt_blacklist```):

```OAUTH_TABLE_BLACKLIST=oauth_jwt_blacklist```

Now execute on your terminal this command: ```php artisan migratre```

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

### Development

Want to contribute? Great!

The project using a simple code.
Make a change in your file and be careful with your updates!
**Any new code will only be accepted with all viladations.**

To ensure that the entire project is fine:

First install all the dev dependences
```sh
composer install --dev --prefer-dist
```

Second run all validations
```sh
composer check
```

**Kiwfy - Open your code, open your mind!**
