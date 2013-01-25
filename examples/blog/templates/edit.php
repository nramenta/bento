<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Edit Post | <?php echo e(config('blog_title')) ?></title>
  <link rel="stylesheet" href="<?php echo url_for('/style.css') ?>">
</head>
<body>
<div class="container">

  <p>
    <a href="<?php echo url_for('/') ?>">home</a> |
    <a href="<?php echo url_for('/posts/new') ?>">create new post</a> |
    <a onclick="return logoutConfirm();" href="<?php echo url_for('/logout') ?>">logout</a>
  </p>

  <hr>

  <h1>Edit Post</h1>

  <?php if (isset($notice)): ?>
  <p class="notice"><?php echo e($notice) ?></p>
  <?php endif ?>

  <?php if (isset($alert)): ?>
  <p class="error"><?php echo e($alert) ?></p>
  <?php endif ?>

  <form method="post" action="<?php echo url_for() ?>">
    <table>
      <tr>
        <th class="align-top"><label for="title">Title</label></th>
        <td>
          <input type="text" id="title" name="title" value="<?php echo e($inputs['title']) ?>" style="width:450px;">
          <?php if ($errors['title']): ?>
          <p class="error">Invalid blog title</p>
          <?php endif ?>
        </td>
      </tr>
      <tr>
        <th class="align-top"><label for="body">Body</label></th>
        <td>
          <textarea id="body" name="body" rows="6" cols="60" style="width:450px;"><?php echo e($inputs['body']) ?></textarea>
          <?php if ($errors['body']): ?>
          <p class="error">Invalid text body</p>
          <?php endif ?>
        </td>
      </tr>
      <tr>
        <th></th>
        <td>
          <input type="hidden" name="id" value="<?php echo e($inputs['id']) ?>">
          <?php echo csrf_field() ?>
          <input type="submit" value="Save Post">
        </td>
      </tr>
    </table>
  </form>

  <p>
    <a onclick="return deleteConfirm();" href="<?php echo url_for('/posts/' . e($inputs['id']) . '/delete?' . csrf_qs()) ?>">delete</a> |
    <a href="<?php echo url_for('/posts/' . e($inputs['id'])) ?>">permalink</a> |
    <a href="<?php echo url_for('/') ?>">index</a>
  </p>

  <hr>

  <p><?php echo e(config('footer')) ?></p>

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
