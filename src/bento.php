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
 * configuration and return the old value. Pass a single argument as key to
 * return its value. Returns null for unrecognized configuration key.
 *
 * @param string $key   Configuration key
 * @param mixed  $value Configuration value
 *
 * @return mixed
 */
function config($key = null, $value = null)
{
    static $storage = array(
        '_flash' => '_flash',
        '_csrf'  => '_csrf',
    );

    if (func_num_args() > 1) {
        $old = isset($storage[$key]) ? $storage[$key] : null;
        $storage[$key] = $value;
        return $old;
    } elseif (func_num_args()) {
        return isset($storage[$key]) ? $storage[$key] : null;
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
        throw new \RuntimeException('Invalid callable');
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
function flash_redirect($vars, $url = null, $code = 302, $delay = 0)
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
 * @param string $url   Redirect URL; defaults to current request URL
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 */
function flash_redirect_to($vars, $path, $code = 302, $delay = 0)
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
    if (!isset($_SESSION)) return false;

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
 * @param string $method Expected request method (optional)
 *
 * @return mixed Either a string representing the request method or a bool
 */
function request_method($method = null)
{
    return isset($method) ?
        $method === $_SERVER['REQUEST_METHOD'] : $_SERVER['REQUEST_METHOD'];
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
 * @param bool Boolean true if yes, false otherwise
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
 * @param array  $args Query string for the returned URL (optional)
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
 * @param mixed    $methods  String or an array of method names
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 *
 * @return mixed
 */
function route($methods = null, $route = null, $callback = null)
{
    static $callbacks = array();

    if (func_num_args() > 2) {
        if (is_array($methods)) {
            foreach ($methods as $method) {
                $callbacks[$route][$method] = $callback;
            }
        } else {
            $callbacks[$route][$methods] = $callback;
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
 * Routes GET, POST, PUT, DELETE, HEAD, and OPTIONS requests.
 *
 * @param string   $route    Route pattern
 * @param callable $callback Route handler callback
 */
function any($route, $callback)
{
    route(array('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'),
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
        if (!headers_sent()) header('Content-Length: ' . $content_length);
    } else {
        while (ob_get_level()) ob_end_flush();
    }
}


// ## Redirection

/**
 * Redirects to a given URL with configurable HTTP response code and time delay.
 *
 * @param string $url   Redirect URL
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 */
function redirect($url = null, $code = 302, $delay = 0)
{
    $url = isset($url) ? $url : url_for();

    if ($delay) {
        header('Refresh: '. $delay .'; url=' . $url, true);
    } else {
        header('Location: ' . $url, true, $code);
        halt($code);
    }
    return true;
}

/**
 * Redirects to the URL of a given path.
 *
 * @param string $path  Redirect path
 * @param int    $code  HTTP redirect code; defaults to 302
 * @param int    $delay Refresh header value in seconds (optional)
 */
function redirect_to($path, $code = 302, $delay = 0)
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
            $_SESSION[$csrf] = sha1(uniqid(mt_rand(), true));
        }
    }

    return $_SESSION[$csrf];
}

/**
 * Returns an HTML hidden input field containing a CSRF token. The name of the
 * hidden input field is defined by the '_csrf' config key.
 *
 * @param string $name  Hidden field input name (optional)
 * @param bool   $renew Flag to renew the CSRF token; defaults to false
 *
 * @return string
 */
function csrf_field($name = null, $renew = false)
{
    $csrf = $name ?: config('_csrf');

    return '<input type="hidden" name="' . e($csrf) . '" ' .
        'value="' . e(csrf_token($renew)) . '">';
}

/**
 * Returns a URL-encoded query string containing a CSRF token. The name of the
 * parameter is defined by the '_csrf' config key.
 *
 * @param string $name  Hidden field input name (optional)
 * @param bool   $renew Flag to renew the CSRF token; defaults to false
 *
 * @return string
 */
function csrf_qs($name = null, $renew = false)
{
    $csrf = $name ?: config('_csrf');

    return urlencode($csrf) . '=' . urlencode(csrf_token($renew));
}

/**
 * Prevents CSRFs on POST and GET requests by matching the server's CSRF token
 * with the one sent in with the request. The name of the POST or GET input to
 * match is defined by the '_csrf' config key. This function will call `halt()`
 * if a CSRF error is detected and therefore would not return.
 *
 * @param string $name POST or GET variable to match (optional)
 *
 * @return bool|null Boolean true on success, null otherwise (does not return)
 */
function prevent_csrf($name = null)
{
    $csrf = $name ?: config('_csrf');

    $token = csrf_token();

    if (!isset($token)) {
        halt(400, 'csrf');
    }

    if (request_method('POST')) {
        if (!isset($_POST[$csrf]) || $_POST[$csrf] != $token) {
            halt(400, 'csrf');
        }
    } elseif (request_method('GET')) {
        if (!isset($_GET[$csrf]) || $_GET[$csrf] != $token) {
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
 * Returns a rendered PHP template as a string. Throws a RuntimeException on
 * invalid files.
 *
 * @param string $file PHP template file
 * @param array  $data Array of key-value template data
 *
 * @return string
 */
function render_template($file, $data = array())
{
    if (!is_readable($file)) {
        throw new \RuntimeException(sprintf(
            'template file %s is not readable', $file));
    }

    extract($data);
    ob_start();
    include func_get_arg(0);
    return ob_get_clean();
}

/**
 * Displays a rendered PHP template.
 *
 * @param string $file PHP template file
 * @param array  $data Array of key-value template data
 */
function display_template($file, $data = array())
{
    echo render_template($file, $data);
}

/**
 * Sends a "204 No Content" response and closes the connection. All outputs are
 * flushed and should not contain anything at all. HTTP headers are all sent
 * by the end of the function. At least one session operation, if any, should
 * precede the call to this function. Failure to do so will result in a PHP
 * warning if you're using session cookies.
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

