<?php

function auth(&$user = null)
{
    if (!isset($_SESSION)) session_start();
    if (func_num_args()) {
        if (isset($_SESSION['auth'])) {
            $user = $_SESSION['auth'];
            return true;
        }
        return false;
    }
    return isset($_SESSION['auth']);
}

function db($sql = null)
{
    static $db;

    if (!isset($db)) {

        try {
            $db = new SQLite3(__DIR__ . '/data.db', SQLITE3_OPEN_READWRITE);
        } catch (\Exception $e) {
            die('No database file found. please check for your installation.');
        }
    }

    if (isset($sql)) {
        return $db->query($sql);
    } else {
        return $db;
    }
}

function get_limit_offset(&$limit, &$offset, &$page)
{
    $page   = isset($_GET['page']) ? max((int)$_GET['page'], 1) : 1;
    $limit  = config('limit');
    $offset = ($page - 1) * $limit;
}

function display($file, $data = array())
{
    display_template(__DIR__ . "/templates/$file", $data + array(
        'errors' => flash('errors'),
        'inputs' => flash('inputs'),
        'notice' => flash('notice'),
        'alert'  => flash('alert'),
    ));
}

function htmlize($text)
{
    $text = preg_replace("/\r\n|\n|\r/", "\n", $text);

    $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

    // links
    $text = preg_replace('#https?://[^\s\)]+#s', '<a href="$0">$0</a>', $text);

    // line breaks
    $text = preg_replace("/(?<!\n)\n(?!\n)/", '<br>', $text);

    // paragraphs
    $text = '<p>' . preg_replace("/(.+)\n\n/", '$1</p><p>', $text) . '</p>';

    return $text;
}

function login($username, $password)
{
    if ($username != config('username') || $password != config('password')) {
        return false;
    }

    if (!isset($_SESSION)) session_start();

    session_regenerate_id(true);

    $_SESSION['auth'] = true;

    return true;
}

function logout()
{
    if (!isset($_SESSION)) session_start();

    $_SESSION = array();

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            config('session_cookie_path'), config('session_cookie_domain'),
            config('session_cookie_secure'), config('session_cookie_httponly')
        );
    }

    session_destroy();

    return true;
}

function get_all_posts(&$posts, $limit, $offset)
{
    $result = db("SELECT * FROM `posts` ORDER BY `tstamp` DESC LIMIT $limit OFFSET $offset");

    if ($result === false) {
        return false;
    }

    $posts = array();

    while($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $posts[] = $row;
    }

    return true;
}

function get_total_post_count(&$total)
{
    $result = db('SELECT COUNT(*) AS `total` FROM `posts`');

    if ($result === false) {
        return false;
    }

    $row = $result->fetchArray(SQLITE3_ASSOC);

    $total = $row['total'];

    return true;
}

function get_pagination(&$older, &$newer, $page, $total)
{
    if ($page < $total) $older = true;
    if ($page > 1) $newer = true;
}

function get_post(&$post, $id)
{
    $db = db();

    $result = $db->query('SELECT * FROM `posts` WHERE `id` = ' . $db->escapeString((int)$id));

    if ($result === false) {
        return false;
    }

    $post = $result->fetchArray(SQLITE3_ASSOC);

    return true;
}

function get_post_title(&$title, $id)
{
    $db = db();

    $result = $db->query('SELECT `title` FROM `posts` WHERE `id` = ' . $db->escapeString((int)$id));

    if ($result === false) {
        return false;
    }

    $row = $result->fetchArray(SQLITE3_ASSOC);

    $title = $row['title'];

    return true;
}

function get_var($key, $default = null)
{
    return isset($_GET[$key]) ? $_GET[$key] : $default;
}

function post_var($key, $default = null)
{
    return isset($_POST[$key]) ? $_POST[$key] : $default;
}

function validate_post($post, &$errors)
{
    $title = $post['title'];
    $body  = $post['body'];

    $errors = array(
        'title' => !strlen($title),
        'body'  => !strlen($body),
    );

    if ($errors['title'] || $errors['body']) {
        return false;
    }
    return true;
}

function save_post($post)
{
    $db = db();

    $id    = $db->escapeString($post['id']);
    $title = $db->escapeString($post['title']);
    $body  = $db->escapeString($post['body']);

    return $db->exec("UPDATE `posts` SET `title` = '$title', `body` = '$body' WHERE `id` = $id");
}

function create_post($post, &$id = null)
{
    $db = db();

    $title  = $db->escapeString($post['title']);
    $body   = $db->escapeString($post['body']);
    $tstamp = $_SERVER['REQUEST_TIME'];

    if ($db->exec("INSERT INTO `posts` (`title`, `body`, `tstamp`) VALUES ('$title', '$body', $tstamp)")) {
        $id = $db->lastInsertRowID();
        return true;
    }
    return false;
}

function delete_post($id)
{
    $db = db();

    $id = (int)$id;

    return $db->exec("DELETE FROM `posts` WHERE `id` = $id");
}

