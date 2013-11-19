<?php
/**
 * Bento - A simple PHP micro-framework.
 *
 * @author  Nofriandi Ramenta <nramenta@gmail.com>
 * @license http://en.wikipedia.org/wiki/MIT_License MIT
 */

// ## Configuration

/**
 * Gets or sets a config value. Pass two arguments as key and value to set a
 * configuration and return the old value. Pass a string as key to return its
 * value. Pass an array of key-value pairs to bulk update configuration keys.
 * Returns null for unrecognized configuration key.
 *
 * @param string $key   Configuration key
 * @param mixed  $value Configuration value
 *
 * @return mixed
 */
function config($key = null, $value = null)
{
    static $storage = array(
        '_flash'  => '_flash',
        '_csrf'   => '_csrf',
        '_method' => '_method',
    );

    if (func_num_args() > 1) {
        $old = isset($storage[$key]) ? $storage[$key] : null;
        $storage[$key] = $value;
        return $old;
    } elseif (func_num_args()) {
        if (is_array($key)) {
            $storage = $key + $storage;
        } else {
            return isset($storage[$key]) ? $storage[$key] : null;
        }
    } else {
        return $storage;
    }
}

// ## Callables

/**
 * Runs a callable with an array of arguments. Throws a RuntimeError on invalid
 * callables.
 *
 * @param callable $callable Callable to run
 * @param array    $args     Arguments for the callable
 *
 * @return mixed Any value returned from the callback
 */
function apply($callable, $args = array())
{
    if (!is_callable($callable)) {
        throw new \RuntimeException('invalid callable');
    }
    return call_user_func_array($callable, $args);
}

/**
 * Runs a callable with a variable number of arguments.
 *
 * @param callable $callable Callable to run
 * @param mixed    $arg      Argument for the callback
 * @param mixed    $arg,...  Unlimited optional arguments for the callback
 *
 * @return mixed Any value returned from the callback
 */
function call($callable, $arg = null)
{
    $args = func_get_args();
    $callable = array_shift($args);
    return apply($callable, $args);
}

// ## Flash session storage

/**
 * Gets or sets a flash value for the current request *and* the next request.
 * Pass two arguments as key and value to set a flash value. Pass a single
 * argument as key to return its value.
 *
 * @param string $key   Flash key
 * @param mixed  $value Flash value
 * @param bool   $keep  Keep the flash for the next request; defaults to true
 *
 * @return mixed
 */
function flash($key = null, $value = null, $keep = true)
{
    static $storage = array();

    if (!isset($_SESSION)) session_start();

    $flash = config('_flash');

    if (func_num_args() > 1) {
        $old = isset($_SESSION[$flash][$key]) ? $_SESSION[$flash][$key] : null;
        if (isset($value)) {
            $_SESSION[$flash][$key] = $value;
            if ($keep) {
                $storage[$key] = $value;
            } else {
                unset($storage[$key]);
            }
        } else {
            unset($storage[$key]);
            unset($_SESSION[$flash][$key]);
        }
        return $old;
    } elseif (func_num_args()) {
        return isset($_SESSION[$flash][$key]) ? $_SESSION[$flash][$key] : null;
    } else {
        return $storage;
    }
}

/**
 * Sets multiple flash values and redirects to a given URL.
 *
 * @param array  $vars  Flash variables
 * @param string $url   Redirect URL; defaults to current request URL
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 */
function flash_redirect($vars, $url = null, $code = 302, $delay = null)
{
    foreach ($vars as $key => $value) {
        $delay ? flash_now($key, $value) : flash($key, $value);
    }
    return redirect($url, $code, $delay);
}

/**
 * Sets multiple flash values and redirects to the URL of a given path.
 *
 * @param array  $vars  Flash variables
 * @param string $path  Redirect path; defaults to current request path
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 */
function flash_redirect_to($vars, $path, $code = 302, $delay = null)
{
    return flash_redirect($vars, url_for($path), $code, $delay);
}

/**
 * Gets or sets a flash value only for the current request. Pass two arguments
 * as key and value to set a flash value. Pass a single argument as key to
 * return its value.
 *
 * @param string $key   Flash key
 * @param mixed  $value Flash value
 *
 * @return mixed
 */
function flash_now($key = null, $value = null)
{
    if (!isset($_SESSION)) session_start();

    $flash = config('_flash');

    if (func_num_args() > 1) {
        return flash($key, $value, false);
    } elseif (func_num_args()) {
        return flash($key);
    } else {
        return isset($_SESSION[$flash]) && is_array($_SESSION[$flash]) ?
            $_SESSION[$flash] : array();
    }
}

/**
 * Keeps a specific or all flash values on to the next request.
 *
 * @param string $key Flash key; leave empty to keep all flash values
 *
 * @return bool Boolean true on success, false otherwise
 */
function flash_keep($key = null)
{
    if (func_num_args()) {
        return !is_null(flash($key, flash($key), true));
    } else {
        foreach (flash_now() as $key => $value) {
            flash($key, $value, true);
        }
    }
    return true;
}

/**
 * Discards a specific or all flash values by the end of the current request.
 *
 * @param string $key Flash key; leave empty to discard all flash values
 *
 * @return bool Boolean true on success, false otherwise
 */
function flash_discard($key = null)
{
    if (func_num_args()) {
        return !is_null(flash($key, flash($key), false));
    } else {
        foreach (flash() as $key => $value) {
            flash($key, $value, false);
        }
    }
    return true;
}

/**
 * Removes a specific or all flash values immediately.
 *
 * @param string $key Flash key; leave empty to remove all flash values
 *
 * @return bool Boolean true on success, false otherwise
 */
function flash_remove($key = null)
{
    if (func_num_args()) {
        return !is_null(flash($key, null));
    } else {
        $keys = array_merge(array_keys(flash()), array_keys(flash_now()));
        foreach ($keys as $key) {
            flash($key, null);
        }
    }
    return true;
}

/**
 * Writes flash values to the session for persistence.
 *
 * This function is called automatically and *should never* be called manually.
 *
 * @return bool Boolean true on success, false otherwise
 */
function flash_write()
{
    if (!isset($_SESSION)) session_start();

    $flash = config('_flash');

    $data = flash();

    if (empty($data)) {
        unset($_SESSION[$flash]);
    } else {
        $_SESSION[$flash] = $data;
    }

    return true;
}

// ## HTTP, paths and URLs

/**
 * Returns HTTP status string or null for unrecognized HTTP status code.
 *
 * @param int $code HTTP status code
 *
 * @return string|null
 */
function http_status($code = null)
{
    static $codes = array(
        100 => 'Continue', 'Switching Protocols',
        200 => 'OK', 'Created', 'Accepted', 'Non-Authoritative Information',
                'No Content', 'Reset Content', 'Partial Content',
        300 => 'Multiple Choices', 'Moved Permanently', 'Moved Temporarily',
                'See Other', 'Not Modified', 'Use Proxy',
        400 => 'Bad Request', 'Unauthorized', 'Payment Required', 'Forbidden',
                'Not Found', 'Method Not Allowed', 'Not Acceptable',
                'Proxy Authentication Required', 'Request Time-out', 'Conflict',
                'Gone', 'Length Required', 'Precondition Failed',
                'Request Entity Too Large', 'Request-URI Too Large',
                'Unsupported Media Type',
        500 => 'Internal Server Error', 'Not Implemented', 'Bad Gateway',
                'Service Unavailable', 'Gateway Time-out',
                'HTTP Version not supported',
    );

    return isset($codes[$code]) ? $codes[$code] : null;
}

/**
 * Tests if a route matches a given path.
 *
 * @param string $route    Route to match
 * @param string $path     Request path
 * @param array  $matches  Array of matching route segments (optional)
 * @param bool   $redirect Flag to indicate if a redirect is needed (optional)
 *
 * @return bool Boolean true if matches, false otherwise
 */
function route_match($route, $path, &$matches = null, &$redirect = null)
{
    static $replace;
    if (!isset($replace)) {
        $replace = function($match) {
            if ($match['rule'] === '') {
                return '(?P<' . $match['name'] . '>[^\/]+)';
            } elseif ($match['rule'] === '#') {
                return '(?P<' . $match['name'] . '>\d+)';
            } elseif ($match['rule'] === '$') {
                return '(?P<' . $match['name'] . '>[a-zA-Z0-9-_]+)';
            } elseif ($match['rule'] === '*') {
                return '(?P<' . $match['name'] . '>.+)';
            } else {
                return '(?P<' . $match['name'] . '>' . $match['rule'] . ')';
            }
        };
    }

    static $pattern = '/<(?:(?P<rule>.+?):)?(?P<name>[a-z_][a-z0-9_]+)>/i';

    $trailing = preg_match('/\/$/', $route);
    $redirect = $trailing && !preg_match('/\/$/', $path);

    return preg_match(
        '#^' . preg_replace_callback($pattern, $replace, $route) .
        ($trailing ? '?' : null) . '$#',
        urldecode($path), $matches
    );
}

/**
 * Returns the request method or tests if the current request method matches the
 * one given as argument. Request methods are *case sensitive*.
 *
 * @param string $test Expected request method (optional)
 *
 * @return mixed Either a string representing the request method or a bool
 */
function request_method($test = null)
{
    $method = $_SERVER['REQUEST_METHOD'];

    $_method = config('_method');

    if ($method === 'POST') {
        if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'];
        } elseif (isset($_POST[$_method])) {
            $method = $_POST[$_method];
        }
    }

    if (isset($test)) {
        return $test === $method;
    } else {
        return $method;
    }
}

/**
 * Returns the request path or tests if the current request path matches the
 * route pattern given as argument.
 *
 * @param string $route    Route pattern (optional)
 * @param array  $matches  Array of matching route segments (optional)
 * @param bool   $redirect Flag to indicate if a redirect is needed (optional)
 *
 * @return mixed Either a string representing the request path or a bool
 */
function request_path($route = null, &$matches = null, &$redirect = null)
{
    $path = substr($path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
        -(strlen($path)-strlen(base_path())));

    return isset($route) ?
        route_match($route, $path, $matches, $redirect) : $path;
}

/**
 * Returns the base path of the current request.
 *
 * @param string $path Path appended to the returned base path (optional)
 *
 * @return string
 */
function base_path($path = null)
{
    $base_path = config('_base_path');

    if (isset($base_path)) return $base_path . $path;

    $request_uri = $_SERVER['REQUEST_URI'];
    $script_name = $_SERVER['SCRIPT_NAME'];

    return substr($request_uri, 0, strlen(rtrim(dirname($script_name),
        '/\\'))) . $path;
}

/**
 * Returns the base URL of the current request.
 *
 * @return string
 */
function base_url()
{
    return url_for('/');
}

/**
 * Tests if a request was made over SSL.
 *
 * @return bool Boolean true if yes, false otherwise
 */
function is_https()
{
    return isset($_SERVER['HTTPS']) && !empty($_SERVER['HTTPS']) &&
        $_SERVER['HTTPS'] != 'off';
}

/**
 * Tests if the request was made with XMLHttpRequest.
 *
 * @return bool Boolean true if yes, false otherwise
 */
function is_ajax()
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';
}

/**
 * Tests if the request is was made with PJAX.
 *
 * @return bool Boolean true if yes, false otherwise
 */
function is_pjax()
{
    return isset($_SERVER['HTTP_X_PJAX']);
}

/**
 * Returns a single or all dynamic path parameters. Pass a single argument as
 * parameter name to return its value. Pass no arguments to get all parameters
 * as a single associative array. The second argument is used to set the default
 * value for the parameter.
 *
 * @param string $name  Parameter name
 * @param string $value Parameter default value; defaults to null
 *
 * @return string|null
 */
function params($name = null, $value = null)
{
    static $params = array();

    if (func_num_args() > 1) {
        if (!isset($params[$name])) {
            $params[$name] = $value;
        }
        return $params[$name];
    } elseif (func_num_args()) {
        return isset($params[$name]) ? $params[$name] : null;
    } else {
        return $params;
    }
}

/**
 * Returns the fully-qualified URL for a specific path. To get the URL of the
 * current request, pass null as the first argument. Query string array passed
 * as the second argument overrides existing ones.
 *
 * @param string $path Path for the returned URL (optional)
 * @param array  $args Array of key-value query strings (optional)
 *
 * @return string
 */
function url_for($path = null, $args = array())
{
    if (func_num_args() === 1) {
        if (is_array(func_get_arg(0))) {
            $path = null;
            $args = func_get_arg(0);
        }
    }

    $schema = is_https() ? 'https://' : 'http://';

    $host = $_SERVER['HTTP_HOST'];

    $parts = parse_url(
        $schema . $host .
        ($path ? base_path($path) : $_SERVER['REQUEST_URI'])
    );

    if (isset($parts['query'])) {
        parse_str($parts['query'], $query);
        $query = array_merge($query, $args);
    } else {
        $query = $args;
    }

    if ($query) {
        $parts['query'] = http_build_query($query);
    }

    return $schema . $host . $parts['path'] .
        (isset($parts['query']) ? '?' . $parts['query'] : null) .
        (isset($parts['fragment']) ? '#' . $parts['fragment'] : null);
}

// ## Routing

/**
 * Maps a route to a callback.
 *
 * @param string|array $methods  String or an array of method names
 * @param string|array $routes   String or an array of route patterns
 * @param callable     $callback Route handler callback
 *
 * @return mixed
 */
function route($methods = null, $routes = null, $callback = null)
{
    static $callbacks = array();

    if (is_string($methods)) {
        $methods = array($methods);
    }

    if (is_string($routes)) {
        $routes = array($routes);
    }

    if (func_num_args() > 2) {
        foreach ($routes as $route) {
            foreach ($methods as $method) {
                $callbacks[$route][$method] = $callback;
            }
        }
    } else {
        return $callbacks;
    }
}

/**
 * Routes GET requests and acts as the fallback router for HEAD requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function get($route, $callback)
{
    route('GET', $route, $callback);
}

/**
 * Routes POST requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function post($route, $callback)
{
    route('POST', $route, $callback);
}

/**
 * Routes both GET and POST requests with automatic CSRF protection.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function form($route, $callback)
{
    route(array('GET', 'POST'), $route, function() use (&$callback) {
        request_method('POST') && prevent_csrf();
        apply($callback, func_get_args());
    });
}

/**
 * Routes PUT requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function put($route, $callback)
{
    route('PUT', $route, $callback);
}

/**
 * Routes PATCH requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function patch($route, $callback)
{
    route('PATCH', $route, $callback);
}

/**
 * Routes DELETE requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function delete($route, $callback)
{
    route('DELETE', $route, $callback);
}

/**
 * Routes HEAD requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function head($route, $callback)
{
    route('HEAD', $route, $callback);
}

/**
 * Routes OPTIONS requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function options($route, $callback)
{
    route('OPTIONS', $route, $callback);
}

/**
 * Routes GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function any($route, $callback)
{
    route(array('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'),
        $route, $callback);
}

/**
 * Registers a callback to the 'before' event.
 *
 * @param callable $callback 'before' event handler callback
 *
 * @return mixed
 */
function before($callback = null)
{
    static $before;
    if (func_num_args()) {
        $before = $callback;
    } else {
        return $before;
    }
}

/**
 * Registers a callback to the 'after' event.
 *
 * @param callable $callback 'after' event handler callback
 *
 * @return mixed
 */
function after($callback = null)
{
    static $after;
    if (func_num_args()) {
        $after = $callback;
    } else {
        return $after;
    }
}

/**
 * Gets or sets an error handler for a specific code. Callback functions can
 * take a message parameter which can be anything from simple strings to complex
 * structures.
 *
 * @param mixed    $code     Halt code, one of HTTP 4xx or 5xx or a string
 * @param callable $callback Halt handler callback
 *
 * @return mixed
 */
function error($code = null, $callback = null)
{
    static $callbacks = array();

    if (func_num_args() > 1) {
        $callbacks[$code] = $callback;
    } elseif (func_num_args()) {
        return isset($callbacks[$code]) ? $callbacks[$code] : null;
    } else {
        return $callbacks;
    }
}

/**
 * Halts the current response, sends any applicable HTTP response code header,
 * calls any custom error handler, and exits.
 *
 * @param mixed $code    Halt code, one of HTTP 4xx or 5xx or a string
 * @param mixed $message Message to be sent to the error handler callback
 */
function halt($code = null, $message = null)
{
    $status = http_status($code);

    if (isset($status)) {
        header("HTTP/1.1 $code $status", true, $code);
    }

    if (($callback = error($code)) !== null) {
        call($callback, $message);
    }

    exit;
}

/**
 * The shutdown function. This functions is registered by `run()` as a shutdown
 * function and therefore *should never* be called directly.
 */
function shutdown()
{
    flash_write();

    if (request_method('HEAD')) {
        $content_length = 0;
        while (ob_get_level()) {
            $content_length += ob_get_length();
            ob_end_clean();
        }
        header('Content-Length: ' . $content_length);
    } else {
        while (ob_get_level()) ob_end_flush();
    }
}


// ## Redirection

/**
 * Redirects to a given URL with configurable HTTP response code and time delay.
 * If a time delay is given, this function will return boolean true, else it
 * will call `halt()` and never returns.
 *
 * @param string $url   Redirect URL
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 *
 * @return bool Boolean true on success
 */
function redirect($url = null, $code = 302, $delay = null)
{
    $url = isset($url) ? $url : url_for();

    if (isset($delay)) {
        header('Refresh: '. $delay .'; url=' . $url, true);
    } else {
        header('Location: ' . $url, true, $code);
        halt($code);
    }

    return true;
}

/**
 * Redirects to the URL of a given path. Acts as a wrapper for the `redirect()`
 * function.
 *
 * @param string $path  Redirect path
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 *
 * @return bool Boolean true if time delay is given
 */
function redirect_to($path, $code = 302, $delay = null)
{
    return redirect(url_for($path), $code, $delay);
}

// ## CSRF protection

/**
 * Returns a CSRF token.
 *
 * @param bool $renew Flag to renew the CSRF token; defaults to false
 *
 * @return string
 */
function csrf_token($renew = false)
{
    if (!isset($_SESSION)) session_start();

    $csrf = config('_csrf');

    if (!isset($_SESSION[$csrf]) || $renew) {
        if (is_callable('openssl_random_pseudo_bytes')) {
            $_SESSION[$csrf] = substr(
                base64_encode(openssl_random_pseudo_bytes(40)), 0, 40
            );
        } else {
            $_SESSION[$csrf] = substr(
                base64_encode(sha1(uniqid(mt_rand(), true))), 0, 40
            );
        }
    }

    return $_SESSION[$csrf];
}

/**
 * Returns an HTML hidden input field containing a CSRF token. The name of the
 * hidden input field is defined by the '_csrf' config key.
 *
 * @param bool $renew Flag to renew the CSRF token; defaults to false
 *
 * @return string
 */
function csrf_field($renew = false)
{
    $csrf = config('_csrf');

    return '<input type="hidden" name="' . e($csrf) . '" ' .
        'value="' . e(csrf_token($renew)) . '">';
}

/**
 * Returns a URL-encoded query string containing a CSRF token. The name of the
 * parameter is defined by the '_csrf' config key.
 *
 * @param bool $renew Flag to renew the CSRF token; defaults to false
 *
 * @return string
 */
function csrf_qs($renew = false)
{
    $csrf = config('_csrf');

    return urlencode($csrf) . '=' . urlencode(csrf_token($renew));
}

/**
 * Prevents CSRFs on POST and GET requests by matching the server's CSRF token
 * with the one sent in with the request. The name of the POST or GET input to
 * match is defined by the '_csrf' config key. This function will call `halt()`
 * if a CSRF error is detected and therefore would not return.
 *
 * @return bool|null Boolean true on success, null otherwise (does not return)
 */
function prevent_csrf()
{
    $csrf = config('_csrf');

    $token = csrf_token();

    if (!isset($token)) {
        halt(400, 'csrf');
    }

    if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
        if ($_SERVER['HTTP_X_CSRF_TOKEN'] !== $token) {
            halt(400, 'csrf');
        }
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST[$csrf]) || $_POST[$csrf] !== $token) {
            halt(400, 'csrf');
        }
    } elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
        if (!isset($_GET[$csrf]) || $_GET[$csrf] !== $token) {
            halt(400, 'csrf');
        }
    }

    return true;
}

// ## Output helpers

/**
 * Returns an HTML-escaped string.
 *
 * @param string $string Original string
 * @param bool   $force  Force-encode existing HTML entities; defaults to false
 *
 * @return string
 */
function e($string, $force = false)
{
    return htmlspecialchars(strval($string), ENT_QUOTES, 'UTF-8', $force);
}

/**
 * Prints an HTML-escaped string.
 *
 * @param string $string Original string
 * @param bool   $force  Force-encode existing HTML entities; defaults to false
 *
 * @return string
 */
function p($string, $force = false)
{
    echo e($string, $force);
}

/**
 * Displays a PHP template. Throws a RuntimeException on invalid files.
 *
 * @param string $file PHP template file
 * @param array  $data Array of key-value template data
 */
function display_template($file, $data = array())
{
    if (!is_readable($file)) {
        throw new \RuntimeException(sprintf(
            'template file %s is not readable', $file
        ));
    }
    extract($data);
    include func_get_arg(0);
}

/**
 * Returns a rendered PHP template as string. 
 *
 * @param string $file PHP template file
 * @param array  $data Array of key-value template data
 *
 * @return string
 */
function render_template($file, $data = array())
{
    ob_start();
    display_template($file, $data);
    return ob_get_clean();
}

/**
 * Sends a "204 No Content" response and closes the connection. All outputs are
 * flushed and should not contain anything at all. HTTP headers are all sent
 * by the end of the function. At least one session operation, if any, should
 * precede the call to this function. Failure to do so will result in a PHP
 * warning if you're using session cookies.
 *
 * @return bool Boolean true on success
 */
function no_content()
{
    header('HTTP/1.1 204 No Content');
    header('Content-Length: 0');
    header('Connection: close');

    while (ob_get_level()) {
        ob_end_clean();
    }
    flush();

    return true;
}

/**
 * Forces the client to not cache the response.
 *
 * @return bool Boolean true on success
 */
function prevent_cache()
{
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Cache-Control: post-check=0, pre-check=0', false);

    return true;
}

// ## File helpers

/**
 * Removes files and directories recursively. If $path is a directory and $rmdir
 * is false, then instead of deleting the directory recursively, this function
 * will only empty the directory.
 *
 * @param string $path  File or directory path
 * @param bool   $rmdir Remove referenced directory, defaults to true
 *
 * @return bool Boolean true on success, false otherwise
 */
function file_remove($path, $rmdir = true)
{
    if (is_file($path) || is_link($path)) {
        return unlink($path);
    } elseif (is_dir($path)) {
        $objects = scandir($path);
        foreach ($objects as $object) {
            if ($object != '.' && $object != '..') {
                file_remove($path . '/' . $object);
            }
        }
        reset($objects);
        return $rmdir ? rmdir($path) : true;
    } else {
        return false;
    }
}

/**
 * File upload handling. Available options are:
 *
 * - size: Exact file size in bytes.
 * - min_size: Minimum file size in bytes.
 * - max_size: Maximum file size in bytes.
 * - types: Allowed mime types, e.g., "image/gif", "image/png".
 * - basename: Base name sans extension.
 * - validator: Callable to file upload validator.
 * - callback: Callable to call instead of having the file automatically moved.
 *
 * @param string $name File input field name
 * @param string $path Either a directory or the destination file path
 * @param array  $opts Rules and options
 *
 * @return string|bool Path to uploaded file on success, boolean false otherwise
 */
function file_upload($name, $path, array $opts = array())
{
    if (!isset($_FILES[$name])) return false;

    if (isset($opts['size'])) {
        $min_size = $max_size = $opts['size'];
    } else {
        $min_size = isset($opts['min_size']) ? $opts['min_size'] : null;
        $max_size = isset($opts['max_size']) ? $opts['max_size'] : null;
    }

    $types = $extensions = array();

    if (isset($opts['types']) && is_array($opts['types'])) {
        foreach ($opts['types'] as $key => $val) {
            if (is_int($key)) {
                $types[] = $val;
            } else {
                $types[] = $key;
                $extensions[$key] = $val;
            }
        }
    }

    $validator = isset($opts['validator']) && is_callable($opts['validator']) ?
        $opts['validator'] : null;

    $callback = isset($opts['callback']) && is_callable($opts['callback']) ?
        $opts['callback'] : null;

    $file = $_FILES[$name];

    if (is_dir($path)) {
        if (substr($path, strlen($path)-1, 1) != DIRECTORY_SEPARATOR) {
            $path .= DIRECTORY_SEPARATOR;
        }
        if (isset($opts['basename'])) {
            if (isset($extensions[$file['type']])) {
                $ext = $extensions[$file['type']];
            } else {
                $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
            }
            $dest = $path . $opts['basename'] . '.' . $ext;
        } else {
            $dest = $path . basename($file['name']);
        }
    } else {
        $dest = $path;
    }

    if ($file['error'] != 0) {
        goto error;
    }

    if (isset($min_size) && $file['size'] < $min_size) {
        goto error;
    }

    if (isset($max_size) && $file['size'] > $max_size) {
        goto error;
    }

    if ($types && !in_array($file['type'], $types)) {
        goto error;
    }

    if (isset($validator) && !call_user_func($validator, $file, $dest, $opts)) {
        goto error;
    }

    if (isset($callback)) {
        return call_user_func($callback, $file, $dest, $opts);
    }

    if (move_uploaded_file($file['tmp_name'], $dest)) {
        return $dest;
    }

    error:
    file_remove($file['tmp_name']);
    return false;
}

/**
 * Forces the download of a file to the client. If the path is not given, then
 * only the appropriate headers will be tranmitted to the client. This is useful
 * to stream contents that is not necessarily a physical file on the server as a
 * file download to the client.
 *
 * @param string $filename Filename
 * @param string $path     Path to file (optional)
 * @param int    $chunks   Number of bytes to flush at a time, defaults to 4096
 *
 * @return bool Boolean true on success, false otherwise
 */
function file_download($filename, $path = null, $chunks = 4096)
{
    // Required for some browsers
    if (ini_get('zlib.output_compression')) {
        @ini_set('zlib.output_compression', 'Off');
    }

    header('Pragma: public');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');

    // Required for certain browsers
    header('Cache-Control: private', false);

    header('Content-Disposition: attachment; filename="' .
        basename(str_replace('"', '', $filename)) . '";');
    header('Content-Type: application/force-download');
    header('Content-Transfer-Encoding: binary');

    if (isset($path)) {
        if (is_readable($path)) {
            header('Content-Length: ' . filesize($path));

            while(ob_get_level()) {
                ob_end_clean();
            }

            $file = fopen($path, 'rb');
            if (!$file) return false;
            while (!feof($file)) {
                echo ($buffer = fread($file, $chunks));
                flush();
            }
            fclose($file);
            return true;
        }
        return false;
    }

    return true;
}

// ## Form helpers

/**
 * Recursively tests if an array contains a given value.
 *
 * @param array $array     Array to be tested
 * @param mixed $test      Value to compare
 * @param bool  $strict    Flag to do a strict comparison; defaults to true
 * @param bool  $recursive Flag to test array recursively; defaults to true
 *
 * @return bool Boolean true if an array contains a given value, false otherwise
 */
function form_any(array $array, $test = true, $strict = true, $recursive = true)
{
    foreach ($array as $k => $v) {
        if (is_array($v) && $recursive) {
            if (form_any($v, $test, $strict)) return true;
        } else {
            if ($strict) {
                if ($v === $test) return true;
            } else {
                if ($v == $test) return true;
            }
        }
    }
    return false;
}

/**
 * Tests if a value adheres to a rule. Rules can be regular expression strings,
 * one of FILTER_VALIDATE_* constants available from PHP's builtin filter
 * extension, or a boolean returning closure object.
 *
 * @param mixed $value Value to test
 * @param mixed $rule  Rule to test
 *
 * @return bool Boolean true if the value passes test, false otherwise
 */
function form_test($value, $rule)
{
    if (is_string($rule)) {
        switch ($rule) {
        case 'optional': $pattern = '/^.*$/s'; break;
        case 'required': $pattern = '/^.+$/s'; break;
        case 'digits'  : $pattern = '/^\d+$/'; break;
        case 'alphanum': $pattern = '/^[a-z0-9]+$/i'; break;
        case 'email'   : $rule = FILTER_VALIDATE_EMAIL; goto email;
        default: $pattern = $rule;
        }
        $validator = function($value) use ($pattern) {
            return preg_match($pattern, $value);
        };
    } elseif (is_int($rule)) {
        email:
        $validator = function($value) use ($rule) {
            return filter_var($value, $rule) !== false;
        };
    } elseif (is_array($rule)) {
        $validator = function($value) use ($rule) {
            array_unshift($rule, $value);
            return call_user_func_array('filter_var', $rule) !== false;
        };
    } elseif ($rule instanceof \Closure) {
        $validator = $rule;
    } else {
        throw new \InvalidArgumentException('unknown rule');
    }

    return (bool) call_user_func($validator, $value);
}

/**
 * Validate form data according to a set of rules. This function can also be
 * used to validate arbitrary data, not just form data. Nested data and rules
 * are also supported, as well as array data. Rules can either be a regular
 * expression pattern, an integer filter for `filter_var()`, or a `Closure`
 * object. If the data is not found, then the value to be tested is null.
 *
 * Example:
 *
 * $data = array(
 *     'name' => 'John Doe',
 *     'age'  => 30,
 * );
 *
 * $rule = array(
 *     'name' => 'required',
 *     'age'  => 'digits',
 * );
 *
 * $valid = form_validate($data, $rule, $errors);
 *
 * if ($valid) {
 *     // data is valid, do what you must do.
 * }
 *
 * The variable $valid will evaluates to `true` while $errors will have the
 * following structure:
 *
 * array(
 *     'name' => false,
 *     'age'  => false
 * )
 *
 * The $errors variable contains error flags. `true` means the input does not
 * conform to the rule while `false` means the input *does* conform to the rule.
 *
 * Although it may seem backwards (i.e., false means OK), this structure gives
 * us the convenience of outputting error messages in our templates, using plain
 * PHP, as follows:
 *
 * <?php if $errors['name'] ?>
 * <p>The name field is required.</p>
 * <?php endif ?>
 *
 * The above rules 'required' and 'integer' are builtin shortcuts to the string
 * '/^.+$/' and '/^\d+$/' respectively.
 *
 * @param array $data   Set of key-value data to be validated
 * @param array $rules  Set of key-value rules
 * @param array $errors Set of returned error flags (optional)
 *
 * @return bool Boolean true if the data is valid, false otherwise
 */
function form_validate(array $data, array $rules, &$errors = array())
{
    if (!isset($errors)) $errors = array();

    $pattern = '/^([a-zA-Z0-9-_ ]+)\[(?:(\d+)?(?:(,)(\d+)?)?)?\]$/';

    foreach ($rules as $key => $rule) {

        $array = false;
        $min = $max = false;
        if (preg_match($pattern, $key, $match)) {
            $key = $match[1];
            if (isset($match[2])) {
                $min = $match[2] == '' ? 0 : $match[2];
            }
            if (isset($match[3])) {
                $max = false;
            } else {
                $max = $min;
            }
            if (isset($match[4])) {
                $max = $match[4];
            }
            $array = true;
        }

        if (!isset($data[$key])) $data[$key] = null;

        if ($array) {
            if (!isset($errors[$key]) || !is_array($errors[$key])) {
                $errors[$key] = array();
            }
            $errors[$key]['count'] = false;
            if (is_array($data[$key])) {
                if ($min !== false && count($data[$key]) < $min) {
                    $errors[$key]['count'] = true;
                }
                if ($max !== false && count($data[$key]) > $max) {
                    $errors[$key]['count'] = true;
                }
                foreach ($data[$key] as $value) {
                    if (is_array($value)) {
                        if (is_array($rule)) {
                            form_validate($value, $rule, $errors[$key][]);
                        } else {
                            $errors[$key][] = true;
                        }
                    } else {
                        if (is_array($rule)) {
                            $errors[$key][] = true;
                        } else {
                            $errors[$key][] = !form_test($value, $rule);
                        }
                    }
                }
            } else {
                $errors[$key]['count'] = true;
            }
        } else {
            if (is_array($data[$key])) {
                if (is_array($rule)) {
                    form_validate($data[$key], $rule, $errors[$key]);
                } else {
                    $errors[$key] = true;
                }
            } else {
                if (is_array($rule)) {
                    $errors[$key] = true;
                } else {
                    $errors[$key] = !form_test($data[$key], $rule);
                }
            }
        }
    }

    return !form_any($errors);
}

/**
 * Returns a zipped array from a set of input arrays.
 *
 * Two input arrays, `[1,2,3]` and `['a','b','c']` will be zipped as:
 *
 * `[[1,'a'], [2,'b'], [3,'c']]`
 *
 * By default, uneven number of elements are included in the final result. If
 * you want to skip sets that are missing values from the final result, pass
 * `true` as the second argument. Individual elements of the resulting zipped
 * array will inherit keys derived from the `$items` argument. The following:
 *
 * `form_zip(['letter' => ['A','B'], 'number' => [1,2]])`
 *
 * Will return the array:
 *
 * `[['letter' => 'A', 'number' => 1], ['letter' => 'B', 'number' => 2]]`
 *
 * @param array $data Set of input arrays
 * @param bool  $skip Skip sets that are missing values; defaults to false
 *
 * @return array
 */
function form_zip(array $data, $skip = false)
{
    $invalids = array();
    $keys = array_keys($data);
    $i = -1;
    $indices = array_reduce($data, function($init, $row) use (&$invalids, &$i) {
        $i += 1;
        if (!is_array($row)) {
            $invalids[] = $i;
            return $init;
        }
        return array_unique(array_merge($init, array_keys($row)));
    }, array());

    if (!empty($invalids)) {
        foreach ($invalids as $i) {
            unset($data[$keys[$i]]);
        }
        $keys = array_keys($data);
    }

    $zipped = array();
    foreach ($indices as $i) {
        $zip = array();
        foreach ($keys as $k) {
            if (isset($data[$k][$i])) {
                $zip[$k] = $data[$k][$i];
            } elseif (!$skip) {
                $zip[$k] = null;
            } else {
                goto skip;
            }
        }
        $zipped[$i] = $zip;
        skip:
    }
    return $zipped;
}

/**
 * Returns a key-filtered array from an input array. Key elements can be simple
 * strings or mixed with a mapping of keys and default values for missing input
 * elements. For example:
 *
 * $data = ['name' => 'John Doe', 'password' => 'p4ssw0rd'];
 *
 * $filtered = form_filter($data, ['name', 'email' => 'N/A'])
 *
 * $filtered == ['name' => 'John Doe', 'email' => 'N/A']; // evaluates to true
 *
 * @param array $data   Input array
 * @param array $keys   Array of keys to include with optional default values
 * @param bool  $strict Return null on missing keys; defaults to false
 *
 * @return array|null Filtered data based on keys or null on strictness failure
 */
function form_filter($data, $keys, $strict = false)
{
    $filtered = array();
    foreach ($keys as $k => $v) {
        if (is_int($k)) {
            if (isset($data[$v])) {
                $filtered[$v] = $data[$v];
            } elseif ($strict) {
                return null;
            }
        } else {
            if (isset($data[$k])) {
                $filtered[$k] = $data[$k];
            } else {
                $filtered[$k] = $v;
            }
        }
    }
    return $filtered;
}

// ## Event helpers

/**
 * Gets or sets event handlers. Pass two arguments as event name and handler to
 * register an event handler. Pass a single argument as event name to return its
 * handlers. Returns null for unrecognized event name.
 *
 * @param string   $event    Event name
 * @param callable $callback Event handler callback
 *
 * @return mixed
 */
function event_register($event = null, $callback = null)
{
    static $handlers = array();

    if (func_num_args() > 1) {
        $handlers[$event][] = $callback;
    } elseif (func_num_args()) {
        return isset($handlers[$event]) ? $handlers[$event] : null;
    } else {
        return $handlers;
    }
}

/**
 * Triggers a registered event.
 *
 * @param string $event Event name
 *
 * @return mixed
 */
function event_trigger($event)
{
    $data = func_get_args();
    array_shift($data);

    if ($handlers = event_register($event)) {
        foreach ($handlers as $callback) {
            apply($callback, $data);
        }
    }
}

// ## Dispatcher

/**
 * Dispatches incoming request. This function may trigger the 'before',
 * and 'after' events.
 *
 * @param string $method Request method
 * @param string $path   Request path
 */
function dispatch($method, $path)
{
    $callbacks = route();

    foreach ($callbacks as $route => $methods) {

        if (route_match($route, $path, $matches, $redirect)) {

            if ($redirect) {
                $url = url_for($path . '/' .
                    (isset($_SERVER['QUERY_STRING']) &&
                    strlen($_SERVER['QUERY_STRING']) ?
                    ('?' . $_SERVER['QUERY_STRING']) : ''));
                redirect($url, 301);
            }

            if ($method === 'HEAD') {
                if (isset($methods['HEAD'])) {
                    $callback = $methods['HEAD'];
                } elseif (isset($methods['GET'])) {
                    $callback = $methods['GET'];
                } else {
                    $callback = null;
                }
            } elseif ($method === 'OPTIONS') {
                $allowed = array_keys($methods);
                if (in_array('GET', $allowed) && !in_array('HEAD', $allowed)) {
                    $allowed[] = 'HEAD';
                }
                header('Allow: ' . implode(',', $allowed));
                if (isset($methods['OPTIONS'])) {
                    $callback = $methods['OPTIONS'];
                } else {
                    halt();
                }
            } else {
                $callback = isset($methods[$method]) ? $methods[$method] : null;
            }

            if (!isset($callback)) {
                $allowed = array_keys($methods);
                if (in_array('GET', $allowed) && !in_array('HEAD', $allowed)) {
                    $allowed[] = 'HEAD';
                }
                header('Allow: ' . implode(',', array_keys($methods)));
                halt(405);
            }

            $params = array();

            foreach ($matches as $key => $val) {
                if (is_string($key)) {
                    params($key, $params[$key] = urldecode($val));
                }
            }

            ($before = before()) && apply($before, $params);
            apply($callback, $params);
            ($after = after()) && apply($after, $params);
            return;
        }
    }
    halt(404);
}

/**
 * Prepares the request cycle and runs the dispatcher.
 *
 * @param string $file Path to router script; should generally be __FILE__
 *
 * @return mixed
 */
function run($file)
{
    if (php_sapi_name() === 'cli-server') {
        config('_base_path', '');
        if ($file != $_SERVER['SCRIPT_FILENAME']) {
            return false;
        }
    }

    foreach (array(400, 404, 405, 500, 503) as $code) {
        if (error($code) === null) {
            error($code, function($message = null) use ($code) {
                header('Content-Type: text/plain');
                echo $code, ' ', http_status($code);
                if (isset($message)) echo "\n$message";
            });
        }
    }

    register_shutdown_function('shutdown');

    ob_start();
    dispatch(request_method(), request_path());
}

