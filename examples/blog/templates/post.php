<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title><?php p($post['title']) ?> | <?php p(config('blog_title')) ?></title>
  <link rel="stylesheet" href="<?php echo url_for('/style.css') ?>">
</head>
<body>
<div class="container">

  <p>
    <a href="<?php echo url_for('/') ?>">home</a> |
  <?php if (auth()): ?>
    <a href="<?php echo url_for('/posts/new') ?>">create new post</a> |
    <a onclick="return logoutConfirm();" href="<?php echo url_for('/logout') ?>">logout</a>
  <?php else: ?>
    <a href="<?php echo url_for('/login') ?>">login</a>
  <?php endif ?>
  </p>

  <hr>

  <?php if (isset($notice)): ?>
  <p class="notice"><?php p($notice) ?></p>
  <?php endif ?>

  <?php if (isset($alert)): ?>
  <p class="error"><?php p($alert) ?></p>
  <?php endif ?>

  <div class="post">
    <h1><?php p($post['title']) ?></h1>
    <p class="date">Posted on <?php p(date('Y-m-d H:i', $post['tstamp'])) ?></p>
    <?php echo htmlize($post['body']) ?>
    <p>
      <?php if(auth()): ?>
      <a href="<?php echo url_for('/posts/' . e($post['id']) . '/edit') ?>">edit</a> |
      <a onclick="return deleteConfirm();" href="<?php echo url_for('/posts/' . e($post['id']) . '/delete?' . csrf_qs()) ?>">delete</a> |
      <?php endif ?>
      <a href="<?php echo url_for() ?>">permalink</a>
    </p>
  </div>

  <p><?php p(config('footer')) ?></p>

</div>
<script>
  function deleteConfirm() {
    return confirm("Delete this post?");
  }
  function logoutConfirm() {
    return confirm("Logout now?");
  }
</script>
</body>
</html>
