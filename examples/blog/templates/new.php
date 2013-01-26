<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Create Post | <?php p(config('blog_title')) ?></title>
  <link rel="stylesheet" href="<?php echo url_for('/style.css') ?>">
</head>
<body>
<div class="container">

  <p>
    <a href="<?php echo url_for('/') ?>">home</a> |
    <a onclick="return logoutConfirm();" href="<?php echo url_for('/logout') ?>">logout</a>
  </p>

  <hr>

  <h1>Create Post</h1>

  <?php if (isset($notice)): ?>
  <p class="notice"><?php p($notice) ?></p>
  <?php endif ?>

  <?php if (isset($alert)): ?>
  <p class="error"><?php p($alert) ?></p>
  <?php endif ?>

  <form method="post" action="<?php echo url_for() ?>">
    <table>
      <tr>
        <th class="align-top"><label for="title">Title</label></th>
        <td>
          <input type="text" id="title" name="title" value="<?php p($inputs['title']) ?>" style="width:450px;">
          <?php if ($errors['title']): ?>
          <p class="error">Invalid blog title</p>
          <?php endif ?>
        </td>
      </tr>
      <tr>
        <th class="align-top"><label for="body">Body</label></th>
        <td>
          <textarea id="body" name="body" rows="6" cols="60" style="width:450px;"><?php p($inputs['body']) ?></textarea>
          <?php if ($errors['body']): ?>
          <p class="error">Invalid text body</p>
          <?php endif ?>
        </td>
      </tr>
      <tr>
        <th></th>
        <td>
          <?php echo csrf_field() ?>
          <input type="submit" value="Create Post">
        </td>
      </tr>
    </table>
  </form>

  <hr>
  <p><?php p(config('footer')) ?></p>

</div>
<script>
  function logoutConfirm() {
    return confirm("Logout now?");
  }
</script>
</body>
</html>
