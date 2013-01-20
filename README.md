# Bento - A simple PHP micro framework

Bento provides a simple yet flexible routing system, built-in CSRF prevention,
flash session variables, and numerous little helper functions to make developing
web apps suck less.

## Installation

Bento is self contained; it consists of a single PHP file. Simply copy the file
into your lib or vendor directory, require it from your front controller script,
and you're all set. The alternative is through [composer][Composer]; the minimum
composer.json configuration is:

```
{
    "require": {
        "bento/bento": "@stable"
    }
}
```

PHP 5.3 or newer is required.

### Apache

Minimum .htaccess configuration for mod_rewrite:

```
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>
```

### Nginx + PHP-FPM

Minimum nginx configuration:

```
location / {
    try_file $uri $uri/ /index.php?$query_string;
}
```

If you want to install your application in a subdirectory, for example `myapp`,
do the following:

```
location /myapp {
    try_file $uri $uri/ /myapp/index.php?$query_string;
}
```

### Built-in server

To use the built-in server available in PHP 5.4, invoke the following command
from your terminal:

    > php -S localhost:8000 index.php

Adjust the host and port as necessary. Replace all instances of index.php above
with your front controller file.

## Usage

The canonical "Hello, World!" example:

```php
<?php
require 'path/to/bento.php';

get('/hello/<world>', function($world)
{
    echo 'Hello, ' . e($world);
});

return run(__FILE__);
```

To ensure compatibility with the built-in server in PHP 5.4, always return the
value returned by `run(__FILE__)`. The following usage examples will omit the
`require` and `return run(__FILE__)` parts.

Built-in routing functions to map routes to callbacks:

- `get()`: Routes GET requests and acts as the fallback router for HEAD
  requests.
- `post()`: Routes POST requests.
- `form()`: Routes both GET and POST requests with automatic CSRF protection.
- `put()`: Routes PUT requests.
- `delete()`: Routes DELETE requests.
- `head()`: Routes HEAD requests.
- `options()`: Routes OPTIONS requests.
- `any()`: Routes all the above HTTP methods.

All routes implicitly handle the OPTIONS method. All routing functions take two
parameters:

- `$route`: Route pattern.
- `$callback`: Route handler; it can be any valid PHP callable.

### Route patterns

Routes must always begin with a forward slash. Routes can contain dynamic paths
along with their optional rules. Dynamic paths will be translated to positional
parameters passed on to the route handler. They can also be accessed using the
`params()` function.

The syntax for dynamic paths is:

    <rule:name>

The rule is optional; if you omit it, be sure to also omit the `:` separator.
Named paths without rules matches all characters up to but not including `/`.

Some examples of routes:

    /posts/<#:id>
    /users/<username>
    /pages/about
    /blog/<#:year>/<#:month>/<#:date>/<#:id>-<$:title>
    /files/<*:path>

There are three built-in rules:

- `#`: digits only, equivalent to `\d+`.
- `$`: alphanums and dashes only, equivalent to `[a-zA-Z0-9-_]+`.
- `*`: any characters including `/`, equivalent to `.+`.

Custom rules are defined using regular expressions:

    /users/<[a-zA-Z0-9_]+:username>

Using the `#` character inside a custom rule should be avoided; URL paths cannot
contain any `#` characters as they are interpreted as URL fragments. If you want
to use them to match url-encoded `#` (encoded as `%23`), you must escape them
as `\#`.

Routes are matched first-only, meaning if a route matches the request path then
its route handler will be executed and no more routes will be matched. Requests
that do not match any routes will yield a "404 Not Found" error.

### Automatic 301 redirection

For every route that ends in a forward slash, any request for that route
**not ending** in a forward slash will result in a "301 Moved Permanently"
redirection to the same route ending in a forward slash:

```php
<?php
get('/books/', function()
{
    echo 'Books!';
});
```

In the above example, a request to `/books?page=42` will result in a redirect to
`/books/?page=42`. This behavior is only true if `/books` is not a registered
route. The reverse, however, is never true:

```php
<?php
get('/about', function()
{
    echo 'About Us';
});
```

A request to `/about/` will result in a "404 Not Found" error. This behavior is
consistent with most popular web servers.

### Flash sessions

Flash sessions are key-value session variables that are available for use only
once in a subsequent request and no further. Pass two arguments as key and value
to set a flash session; pass a single argument as key to get a flash session:

```php
<?php
get('/step-1', function()
{
    flash('words', 'available in the very next request, but no further.');
});

get('/step-2', function()
{
    echo 'Your words were ' . flash('words');
});
```

In the above example, when a request to `/step-2` is made right after a request
to `/step-1`, the flash variable `words` is available and set. If the user then
visits any other URL after that, or visits a URL with a route handler that uses
the same flash variable in between those requests, then that flash variable will
yield `null`; it has been used and thus ceased to exist.

### Built-in CSRF prevention

Effortlessly protect your forms against [cross site request forgeries][CSRF]:

```php
<?php
get('/posts/new', function()
{
    $csrf_field = csrf_field();
    // pass this hidden field tag to your HTML form
});
```

The value returned from `csrf_field()` is an HTML hidden field tag. In your POST
route handler, simply call `prevent_csrf()`:

```php
<?php
post('/posts/new', function()
{
    prevent_csrf();
    // create new post ...
});
```

Any CSRF-related errors will result in a "400 Bad Request" invoked automatically
by calling `halt(400, 'csrf')`. Use SSL lest your CSRF tokens be subject to
[man in the middle attacks][MITM].

### Post-Redirect-Get pattern

[Post/Redirect/Get][PRG] is a web development design pattern that prevents some
duplicate form submissions, resulting in a more intuitive user interface:

```php
<?php
form('/posts/<id>', function($id)
{
    if (request_method('POST')) {
        // update the post
        if ($success) {
            flash('notice', 'Post successfully saved. Yay!');
        } else {
            flash('error', 'Something went horribly wrong :(');
        }
        redirect(); // redirect to the current request path
    }

    // display form if the request method is GET
    display_template('post_edit.html', array(
        'notice'     => flash('notice'),
        'error'      => flash('error'),
        'csrf_field' => csrf_field(),
    ));
});
```

There are a number of request, path, URL and redirection helper functions:

- `request_method()`: Gets or tests the current request method.
- `request_path()`: Gets or tests the current request path.
- `route_match()`: Tests if a route matches a request path.
- `base_path()`: Returns the base path.
- `base_url()`: Returns the base URL.
- `is_https()`: Tests if the request was made over SSL.
- `is_ajax()`: Tests if the request was made with XMLHttpRequest.
- `is_pjax()`: Tests if the request was made with PJAX.
- `params()`: Returns a dynamic path variable.
- `url_for()`: Returns the URL for a given path.
- `redirect()`: Redirects to a given URL.
- `redirect_to()`: Redirects to the URL of a given path.

### Output helpers

- `e()`: Returns an HTML-escaped string.
- `render_template()`: Returns a rendered PHP template as a string.
- `display_template()`: Displays a rendered PHP template.
- `no_content()`: Sends a "204 No Content" response and closes the connection.

### Error handling and halt

Halting a request by calling `halt()` will stop execution immediately, call any
custom error handler and perform all the necessary actions to properly exit:

```php
<?php
get('/blog/<#:id>', function($id)
{
    halt('database', 'connection_error');
    // return a 404 response if $id is not found
    halt(404);
});
```

Register custom error handlers with `error()`:

```php
<?php
error(404, function($message = null)
{
    echo '<h1>404 - Page Not Found</h1>';
});

error(400, function($message = null)
{
    echo '<h1>400 - Bad Request</h1>';
    if ($message == 'csrf') {
        echo '<p>CSRF detected!</p>';
    }
});

error('database', function($message = null)
{
    // handle custom database error based on $message
});
```

Passing `halt()` an HTTP error code as the first argument will automatically
send the corresponding HTTP response code header. You can optionally pass an
extra argument to `halt()` which will be passed on to the error handler.

Bento will, by default, handle 400, 404, 405, 500, and 503 HTTP errors.

### Routing events

- `before`: Triggered just before a route handler is about to be called;
  this implies that a route is matched.
- `after`: Triggered just after a route handler is called. If a route
  handler exits prematurely, e.g., by invoking `halt()`, this event is never
  triggered.

The functions `before()` and `after()` are provided as convenience:

```php
<?php
before(function()
{
    echo 'Printed for every matched route prior to the route handler.';
});

after(function()
{
    echo 'As will this, but afer the route handler.';
});
```

### Autoloading

Take advantage of PHP's autoloading functionality by organizing your callbacks
as static methods in classes and register them, e.g., as follows:

```php
<?php
get('/blog/<id>', array('Blog', 'get_post'));
```

The callbacks will then be loaded only when needed. The same can also be done
for error handlers.

## License

Bento is released under the [MIT License][MIT].

## Acknowledgments

Bento is influenced by many web frameworks. Among them are [Rails], [Sinatra],
[Limonade], [Bottle], and [Flask].

[Composer]: http://getcomposer.org/
[CSRF]: http://en.wikipedia.org/wiki/Cross-site_request_forgery
[PRG]: http://en.wikipedia.org/wiki/Post/Redirect/Get
[MIT]: http://en.wikipedia.org/wiki/MIT_License
[MITM]: http://en.wikipedia.org/wiki/Man-in-the-middle_attack

[Rails]: http://rubyonrails.org/
[Sinatra]: http://www.sinatrarb.com/
[Limonade]: http://limonade-php.github.com/
[Bottle]: http://bottlepy.org/docs/dev/
[Flask]: http://flask.pocoo.org/
