<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Delete Post | <?php p(config('blog_title')) ?></title>
  <link rel="stylesheet" href="<?php echo url_for('/style.css') ?>">
</head>
<body>
<div class="container">

  <h1>Delete Post</h1>

  <?php if (isset($notice)): ?>
  <p class="notice"><?php p($notice) ?></p>
  <?php endif ?>

  <p>You will be redirected to the frontpage in a moment...</p>

  <p><a href="<?php echo url_for('/') ?>">Click here</a> to be instantly redirected to the front page.</p>

  <hr>
  <p><?php p(config('footer')) ?></p>

</div>
</body>
</html>
