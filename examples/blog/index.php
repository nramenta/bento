<?php

// report *ALL* errors
error_reporting(-1);

// adjust path to bento.php
require __DIR__ . '/../../src/bento.php';

// application domain specific functions
require __DIR__ . '/functions.php';

// set configration values
foreach (include "config.php" as $key => $value) {
    config($key, $value);
}

get('/', function()
{
    get_limit_offset($limit, $offset, $page);

    get_all_posts($posts, $limit, $offset) or halt(500);

    get_total_post_count($total) or halt(500);

    get_pagination($older, $newer, $page, ceil($total / $limit));

    display('frontpage.php', array(
        'posts' => $posts,
        'page'  => $page,
        'older' => $older,
        'newer' => $newer,
    ));
});

get('/posts/<#:id>', function($id)
{
    get_post($post, $id) or halt(500);

    !empty($post) or halt(404);

    display('post.php', array(
        'post' => $post,
    ));
});

get('/login', function()
{
    display('login.php');
});

post('/login', function()
{
    if (!login(post_var('username'), post_var('password'))) {
        flash('inputs', $_POST);
        flash('errors', array('login' => true));
        redirect_to('/login');
    }

    redirect_to('/');
});

get('/logout', function()
{
    logout() and redirect_to('/');
});

form('/posts/new', function()
{
    auth() or flash_redirect_to(array('errors' => array('auth' => true)), '/login');

    if (request_method('POST')) {

        validate_post(array(
            'title' => $title = post_var('title'),
            'body'  => $body  = post_var('body'),
        ), $errors) or flash_redirect(array(
            'inputs' => $_POST,
            'errors' => $errors,
            'alert'  => 'Error creating new post',
        ));

        $post = array(
            'title'  => $title,
            'body'   => $body,
            'tstamp' => $_SERVER['REQUEST_TIME'],
        );

        create_post($post, $id) and
        flash_redirect_to(array('notice' => 'Post created!'), "/posts/$id") or
        halt(500);
    }

    display('new.php');
});

form('/posts/<#:id>/edit', function($id)
{
    auth() or flash_redirect_to(array('errors' => array('auth' => true)), '/login');

    if (request_method('POST')) {

        validate_post(array(
            'title' => $title = post_var('title'),
            'body'  => $body  = post_var('body'),
        ), $errors) or flash_redirect(array(
            'inputs' => $_POST,
            'errors' => $errors,
            'alert'  => 'Error saving post',
        ));

        $post = array(
            'id'    => $id,
            'title' => $title,
            'body'  => $body,
        );

        save_post($post) and
        flash_redirect(array('notice' => 'Post saved!')) or
        halt(500);
    }

    $post = flash('inputs') or get_post($post, $id) or halt(500);

    !empty($post) or halt(404);

    display('edit.php', array(
        'inputs' => $post,
        'r' => get_var('r')
    ));
});

get('/posts/<#:id>/delete', function($id)
{
    auth() or flash_redirect_to(array('errors' => array('auth' => true)), '/login');

    prevent_csrf();

    get_post_title($title, $id) or halt(500);
    
    !empty($title) or halt(404);

    delete_post($id) and
    flash_redirect_to(array('notice' => "Post titled \"$title\" successfully deleted!"), '/', 302, 5) or
    halt(400, 'database');

    display('delete.php');
});

error(404, function($message = null)
{
    display('error.php', array(
        'title'   => '404 Not Found',
        'message' => 'The page you are looking for is not found.',
    ));
});

error(500, function($message = null)
{
    display('error.php', array(
        'title'   => '500 Server Error',
        'message' => $message,
    ));
});

return run(__FILE__);

