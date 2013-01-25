<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Delete Post | <?php echo e(config('blog_title')) ?></title>
  <link rel="stylesheet" href="<?php echo url_for('/style.css') ?>">
</head>
<body>
<div class="container">

  <h1><?php echo e($title) ?></h1>

  <?php echo e($message) ?>

  <p><a href="<?php echo e(url_for('/')) ?>">Click here</a> to go to the front page.</p>

  <hr>
  <p><?php echo e(config('footer')) ?></p>

</div>
</body>
</html>
