<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login | <?php p(config('blog_title')) ?></title>
  <link rel="stylesheet" href="<?php echo url_for('/style.css') ?>">
</head>
<body>
<div class="container">

  <h1><?php p(config('blog_title')) ?></h1>

  <hr>

  <?php if (isset($errors['login'])): ?>
  <p class="error">Error logging in, wrong username and password combination!</p>
  <?php elseif (isset($errors['auth'])): ?>
  <p class="error">Authorization required; please login first before continuing!</p>
  <?php else: ?>
  <p>Login to create, edit, and delete posts.</p>
  <?php endif ?>

  <form method="post" action="<?php echo url_for('/login') ?>">
    <table>
      <tr>
        <th><label for="username">Username</label></th>
        <td><input type="text" id="username" name="username" value="<?php p($inputs['username']) ?>"></td>
      </tr>
      <tr>
        <th><label for="password">Password</label></th>
        <td><input type="password" id="password" name="password" value=""></td>
      </tr>
      <tr>
        <th></th>
        <td><input type="submit" value="Login"></td>
      </tr>
    </table>
  </form>

  <h4>hint:</h4>
  <p class="hint">Username: <em><?php p(config('username')) ?></em></p>
  <p class="hint">Password: <em><?php p(config('password')) ?></em></p>

  <hr>
  <p><?php p(config('footer')) ?></p>

</div>
</body>
</html>
