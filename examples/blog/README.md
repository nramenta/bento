# Bento Example Blog Application

This example blog application is intended to quickly show you how to build a
simple web application using Bento. It uses SQLite3 for storage and plain PHP
templates. The source code is straight-forward and very easy to follow.

## Installation

The fastest way to run the application is to use PHP 5.4's built-in web server:

```
> php -S localhost:8000 index.php
```

And point your browser to `http://localhost:8000`. If you decide to move the
application directory somewhere else, you'll need to also adjust the path to
Bento found in the `index.php` controller file.

If, for some reason, the `data.db` file is missing, you can recreate it by:

```
> sqlite3 data.db < schema.sql
```

This process requires that you have a SQLite3 CLI binary available.

All configuration is located inside the `config.php` file.

## License

This example application is put under the public domain. You can do anything you
want with it.

