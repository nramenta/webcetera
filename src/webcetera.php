<?php
/*
 * Webcetera - A collection of PHP helper functions.
 *
 * @author  Nofriandi Ramenta <nramenta@gmail.com>
 * @license http://en.wikipedia.org/wiki/MIT_License MIT
 */

// # Super globals

/*
 * Gets a server variable by key.
 *
 * @param mixed $key     $_SERVER variable key
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the variable exists
 *
 * @return mixed
 */
function server_var($key, $default = null, &$found = null)
{
    return array_get($_SERVER, $key, $default, $found);
}

/*
 * Gets a session variable by key.
 *
 * @param mixed $key     $_SESSION variable key
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the variable exists
 *
 * @return mixed
 */
function session_var($key, $default = null, &$found = null)
{
    if (!isset($_SESSION)) session_start();

    return array_get($_SESSION, $key, $default, $found);
}

/*
 * Gets a cookie variable by key.
 *
 * @param mixed $key     $_COOKIE variable key
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the variable exists
 *
 * @return mixed
 */
function cookie_var($key, $default = null, &$found = null)
{
    return array_get($_COOKIE, $key, $default, $found);
}

/*
 * Gets a GET request variable by key.
 *
 * @param mixed $key     $_GET variable key
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the variable exists
 *
 * @return mixed
 */
function get_var($key, $default = null, &$found = null)
{
    $var = array_get($_GET, $key, $default, $found);
    return strlen(trim($var)) ? $var : $default;
}

/*
 * Gets a POST request variable by key.
 *
 * @param mixed $key     $_POST variable key
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the variable exists
 * 
 * @return mixed
 */
function post_var($key, $default = null, &$found = null)
{
    $var = array_get($_POST, $key, $default, $found);
    return strlen(trim($var)) ? $var : $default;
}

/*
 * Gets a REQUEST variable by key.
 *
 * @param mixed $key     $_REQUEST variable key
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the variable exists
 *
 * @return mixed
 */
function request_var($key, $default = null, &$found = null)
{
    $var = array_get($_REQUEST, $key, $default, $found);
    return strlen(trim($var)) ? $var : $default;
}

// ## Form validation functions

/*
 * Parses the input rule string to an array. This function is not meant to be
 * called directly.
 *
 * @param string $rules Set of rules separated by '|' character
 *
 * @return array
 */
function form_parse_rules($rules)
{
    return array_filter(preg_split('/(?<!\\\\)\|/', $rules, -1,
        PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY),
        function($rule) {
            return !empty($rule);
        }
    );
}

/*
 * Determines whether a value is valid given a set of rules.
 *
 * @param mixed $value Value to test
 * @param array $rules Set of rules
 *
 * @return bool Boolean true if input is valid, false otherwise
 */
function form_validate_input($value, $rules)
{
    if (is_string($rules)) {
        $rules = form_parse_rules($rules);
    }

    if (in_array('array', $rules)) {
        if (!is_array($value)) return false;
        $errors = array();
        array_remove($rules, 'array');
        foreach ($value as $val) {
            if (is_scalar($val) || is_null($val)) {
                $errors[] = form_validate_input($val, $rules);
            } else {
                $errors[] = false;
            }
        }
        return $errors;
    } elseif (!(is_scalar($value) || is_null($value))) {
        return false;
    }

    if (in_array('optional', $rules) && !strlen(trim($value))) {
        return true;
    }

    foreach ($rules as $rule) {
        if (preg_match('/^required$/', $rule)) {

            if (!strlen(trim($value))) return false;

        } elseif (preg_match('@^match:(.+)$@', str_replace('\|', '|', $rule),
          $match)) {

            if (!preg_match($match[1], $value)) return false;

        } elseif (preg_match('/^alphanum$/', $rule, $match)) {

            if (!preg_match('/^[a-zA-Z0-9]+$/', $value)) return false;

        } elseif (preg_match('/^alphadash$/', $rule, $match)) {

            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $value)) return false;

        } elseif (preg_match('/^alpha$/', $rule, $match)) {

            if (!preg_match('/[a-zA-Z]+/', $value)) return false;

        } elseif (preg_match('/^digits$/', $rule, $match)) {

            if (!preg_match('/[0-9]+/', $value)) return false;

        } elseif (preg_match('/^natural$/', $rule, $match)) {

            if (!preg_match('/^[1-9][0-9]*$/', $value)) return false;

        } elseif (preg_match('/^numeric$/', $rule, $match)) {

            if (!is_numeric($value)) return false;

        } elseif (preg_match('/^url$/', $rule, $match)) {

            if (!filter_var($value, FILTER_VALIDATE_URL)) return false;

        } elseif (preg_match('/^email$/', $rule, $match)) {

            if (!filter_var($value, FILTER_VALIDATE_EMAIL)) return false;

        } elseif (preg_match('/^date:(.+)$/', $rule, $match)) {

            if (!strlen($value) ||
                date_create($match[1]) != date_create($value)) return false;

        } elseif (preg_match('/^after:(.+)$/', $rule, $match)) {

            if (!strlen($value) ||
                date_create($match[1]) >= date_create($value)) return false;

        } elseif (preg_match('/^before:(.+)$/', $rule, $match)) {

            if (!strlen($value) ||
                date_create($match[1]) <= date_create($value)) return false;

        } elseif (preg_match('/^in:(.+)$/', $rule, $match)) {

            if (!in_array($value, explode(',', $match[1]))) return false;

        } elseif (preg_match('/^not_in:(.+)$/', $rule, $match)) {

            if (in_array($value, explode(',', $match[1]))) return false;

        } elseif (preg_match('/^length:(?:(?J)(?P<min>\d+)-(?P<max>\d+)
            |(?P<min>\d+)\+|(?P<max>\d+)-|(?P<exact>\d+))$/x', $rule, $match)) {

            $exact = isset($match['exact']) && strlen($match['exact']) ?
                $match['exact'] : null;
            $min = isset($match['min']) && strlen($match['min']) ?
                $match['min'] : null;
            $max = isset($match['max']) && strlen($match['max']) ?
                $match['max'] : null;

            if (isset($exact) && strlen(trim($value)) != $exact) return false;
            if (isset($min) && strlen(trim($value)) < $min) return false;
            if (isset($max) && strlen(trim($value)) > $max) return false;

        } elseif (preg_match('/^range:(?:(?J)(?P<min>[+-]?\d+)-(?P<max>[+-]?\d+)
            |(?P<min>[+-]?\d+)\+|(?P<max>[+-]?\d+)-|(?P<exact>[+-]?\d+))$/x',
            $rule, $match)) {

            $exact = isset($match['exact']) && strlen($match['exact']) ?
                $match['exact'] : null;
            $min = isset($match['min']) && strlen($match['min']) ?
                $match['min'] : null;
            $max = isset($match['max']) && strlen($match['max']) ?
                $match['max'] : null;

            if (!is_numeric($value)) return false;
            if (isset($exact) && $value != $exact) return false;
            if (isset($min) && $value < $min) return false;
            if (isset($max) && $value > $max) return false;

        } elseif (preg_match('/^callback:(\w+)$/', $rule, $match)) {

            if (!call_user_func($match[1], $value)) return false;

        }
    }

    return true;
}

/*
 * Determines whether a set of input is valid given their respective rules.
 *
 * @param array $input      Set of input
 * @param array $definition Set of rules
 * @param bool  $errors     Flag to indicate input errors (optional)
 *
 * @return bool Boolean true if all input is valid, false otherwise
 */
function form_validate($input, $definition, &$errors = null)
{
    foreach ($definition as $key => $rules) {
        if (is_array($rules)) {
            form_validate(
                isset($input[$key]) ? $input[$key] : null, $rules, $_errors
            );
            $errors[$key] = $_errors;
            unset($_errors);
        } else {
            $_errors = form_validate_input(
                isset($input[$key]) ? $input[$key] : null, $rules
            );
            if (is_array($_errors)) {
                array_walk($_errors, function(&$item, $key) {
                    $item = !$item;
                });
            } else {
                $_errors = !$_errors;
            }
            $errors[$key] = $_errors;
            unset($_errors);
        }
    }

    $valid = true;
    array_walk_recursive($errors, function(&$item, $key) use (&$valid) {
        $valid = $valid && !$item;
    });
    return $valid;
}

// ## File upload

/*
 * Uploads a file. Rules and options are:
 *
 * - size: Exact file size in bytes.
 * - min_size: Minimum file size in bytes.
 * - max_size: Maximum file size in bytes.
 * - types: Allowed mime types, e.g., "image/gif", "image/png".
 *
 * @param string $name File input field name
 * @param string $path Either a directory or the destination file path
 * @param array  $opts Rules and options
 *
 * @return bool Boolean true on success, false otherwise
 */
function upload_file($name, $path, $opts = array())
{
    if (!isset($_FILES[$name])) return false;

    if (isset($opts['size'])) {
        $min_size = $max_size = $opts['size'];
    } else {
        $min_size = isset($opts['min_size']) ? $opts['min_size'] : null;
        $max_size = isset($opts['max_size']) ? $opts['max_size'] : null;
    }

    $types = isset($opts['types']) ? array_convert($opts['types']) : array();

    $callback = isset($opts['callback']) && is_callable($opts['callback']) ?
        $opts['callback'] : null;

    $file = $_FILES[$name];

    if (is_dir($path)) {
        if (substr($path, strlen($path)-1, 1) != DIRECTORY_SEPARATOR) {
            $path .= DIRECTORY_SEPARATOR;
        }
        $dest = $path . basename($file['name']);
    } else {
        $dest = $path;
    }

    if ($file['error'] != 0) {
        goto error;
    }

    if (isset($min_size) && $file['size'] < $min_size) {
        goto error;
    }

    if (isset($max_size) && $file['size'] > $max_size) {
        goto error;
    }

    if ($types && !in_array($file['type'], $types)) {
        goto error;
    }

    if (isset($callback)) {
        return call_user_func($callback, $file, $dest, $opts);
    }

    return move_uploaded_file($file['tmp_name'], $dest);

    error:
    remove($file['tmp_name']);
    return false;
}

// ## Arrays

/*
 * Converts any type of value to an array.
 *
 * @param mixed $value   Any type of array-convertible value
 * @param mixed $default Default return value; defaults to array()
 *
 * @return array
 */
function array_convert($value, $default = array())
{
    if (is_array($value)) return $value;

    if ($value instanceof \Traversable) {
        return iterator_to_array($value);
    } elseif (is_object($value)) {
        return get_object_vars($value);
    } elseif (is_string($value)) {
        return str_split($value);
    } elseif (is_scalar($value) || is_null($value)) {
        return array($value);
    }

    return $default;
}

/*
 * Determines whether the provided key is a valid key within an array.
 *
 * @param mixed $key   Array key to test
 * @param array $array Array to test
 *
 * @return bool Boolean true if key is valid; false otherwise
 */
function array_key_valid($array, $key)
{
    return (is_scalar($key) || is_null($key)) && is_array($array) &&
        array_key_exists($key, $array);
}

/*
 * Determines whether every value in an array is equal to a given value.
 *
 * @param array $array  Array to test
 * @param mixed $value  Value to test
 * @param bool  $strict Test with strictness; defaults to false
 *
 * @return bool
 */
function array_all($array, $value, $strict = false)
{
    foreach ($array as $el) {
        if ((!$strict && $el != $value) || ($strict && $el !== $value)) {
            return false;
        }
    }
    return true;
}

/*
 * Determines whether at least one value is equal to a given value.
 *
 * @param array $array  Array to test
 * @param mixed $value  Value to test
 * @param bool  $strict Test with strictness; defaults to false
 *
 * @return bool
 */
function array_any($array, $value, $strict = false)
{
    return in_array($value, $array, $strict);
}

/*
 * Works like array_filter except keys are passed as second argument to
 * callback.
 *
 * @param array    $array    Array to filter
 * @param callable $callback Filter function; defaults to null
 *
 * @return array
 */
function array_filter_key($array, $callback = null)
{
    if (!isset($callback)) return array_filter($array);
    if (!is_callable($callback)) return $array;
    $result = array();
    foreach ($array as $key => $value) {
        if (call_user_func_array($callback, array($value, $key))) {
            $result[$key] = $value;
        }
    }
    return $result;
}

/*
 * Returns the first element of an array.
 *
 * @param array $array   Source array
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the first element exists
 */
function array_first($array, $default = null, &$found = null)
{
    if ($array instanceof \Traversable) {
        $array = iterator_to_array($array);
    }

    if (!is_array($array)) {
        $found = false;
        return $default;
    }

    $keys = array_keys($array);
    if ($keys) {
        $found = true;
        return $array[$keys[0]];
    }

    $found = false;
    return $default;
}

/*
 * Flattens an array of any dimension to a one-dimensional array.
 */
function array_flatten()
{
    $flat = array();
    $args = func_get_args();

    if (count($args) === 1 && is_array($args[0])) {
        $args = array_shift($args);
    }

    foreach ($args as $arg) {
        if (is_array($arg)) {
            $flat = array_merge($flat, array_flatten($arg));
        } else {
            $flat[] = $arg;
        }
    }

    return $flat;
}

/*
 * Gets an element of an array. Can also be used to get an element deep inside
 * a multidimensional array by specifying an array of path.
 *
 * @param array $array   Original array
 * @param mixed $path    String or array of path
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate if the value was found (optional)
 *
 * @return mixed
 */
function array_get($array, $path, $default = null, &$found = null)
{
    if ($array instanceof \Traversable) {
        $array = iterator_to_array($array);
    }

    if (!is_array($array)) {
        $found = false;
        return $default;
    }

    if (is_array($path)) {
        foreach ($path as $field) {
            $array = array_get($array, $field, $default, $found);
            if (!$found) break;
        }
        return $array;
    } elseif (array_key_valid($array, $path)) {
        $found = true;
        return $array[$path];
    } else {
        $found = false;
        return $default;
    }
}

/*
 * Returns an array of arrays grouped based on a particular key.
 */
function array_group($array, $key, $preserve_keys = true)
{
    $group = array();
    foreach ($array as $k => $v) {
        if (array_key_valid($v, $key)) {
            if ($preserve_keys === true) {
                $group[$v[$key]][$k] = $v;
            } else {
                $group[$v[$key]][] = $v;
            }
        }
    }
    return $group;
}

/*
 * Returns the last element of an array.
 *
 * @param array $array   Source array
 * @param mixed $default Default return value; defaults to null
 * @param bool  $found   Flag to indicate whether the last element exists
 */
function array_last($array, $default = null, &$found = null)
{
    if ($array instanceof \Traversable) {
        $array = iterator_to_array($array);
    }

    if (!is_array($array)) {
        $found = false;
        return $default;
    }

    $keys = array_keys($array);
    if ($keys) {
        $found = true;
        return $array[$keys[count($keys) - 1]];
    }

    $found = false;
    return $default;
}

/*
 * Plucks an array of arrays based on a key.
 *
 * @param array $array         Array to pluck
 * @param mixed $key           Array key to pluck
 * @param bool  $preserve_keys Preserve keys; defaults to true
 *
 * @return array
 */
function array_pluck($array, $key, $preserve_keys = true)
{
    $pluck = array();
    foreach ($array as $k => $v) {
        if (array_key_valid($v, $key)) {
            if ($preserve_keys === true) {
                $pluck[$k] = $v[$key];
            } else {
                $pluck[] = $v[$key];
            }
        }
    }
    return $pluck;
}

/*
 * Removes elements of an array based on given values.
 *
 * @param array $array     Array variable
 * @param mixed $value     Value to remove
 * @param mixed $value,... Unlimited optional values to remove
 *
 * @return bool Boolean true on success, false otherwise
 */
function array_remove(&$array, $value = null)
{
    $values = func_get_args();
    $array = array_shift($values);
    if (!is_array($array)) return false;

    $keys = array();
    foreach ($values as $value) {
        $keys = array_merge($keys, array_keys($array, $value));
    }
    array_walk($array, function($item, $key) use (&$array, $keys) {
        if (in_array($key, $keys)) unset($array[$key]);
    });
    return true;
}

/*
 * Unzips an array. The reverse of `array_zip()`.
 *
 * @param array $array Array to unzip
 *
 * @return array
 */
function array_unzip($array)
{
    $unzip = array();

    foreach ($array as $element) {
        foreach ($element as $key => $value) {
            $unzip[$key][] = $value;
        }
    }

    return $unzip;
}

/*
 * Returns a new array based on a whitelist of keys.
 *
 * @param array $array Original array
 * @param mixed $keys  Key whitelist
 *
 * @return array
 */
function array_whitelist($array, $keys)
{
    if (func_num_args() == 2 && is_array(func_get_arg(1))) {
        $keys = func_get_arg(1);
        $array = func_get_arg(0);
    } else {
        $keys = func_get_args();
        $array = array_shift($keys);
    }
    return array_intersect_key($array, array_flip($keys));
}

/*
 * Zips arrays. The reverse of `array_unzip()`.
 *
 * @param array $array     Array to unzip
 * @param array $array,... Unlimited optional arrays to unzip
 *
 * @return array
 */
function array_zip($array)
{
    $arrays = func_get_args();

    foreach ($arrays as $i => $array) {
        if (!is_array($array)) {
            throw new \InvalidArgumentException(sprintf(
                'argument %d of %s is not an array',
                $i + 1, __FUNCTION__
            ));
        }
    }

    $keys = array_values(array_reduce(func_get_args(), function($keys, $arg) {
        if (empty($keys)) return array_keys($arg);
        return array_intersect(array_keys($arg), $keys);
    }, array()));

    $args = array_filter(func_get_args(), function($arg) use ($keys) {
        return count(array_intersect(array_keys($arg), $keys)) >= count($keys);
    });

    $zip = array();
    foreach ($keys as $key) {
        foreach ($args as $i => $arg) {
            $zip[$key][$i] = $arg[$key];
        }
    }

    return $zip;
}

/*
 * Zips arrays and combine with keys each element of the zipped array.
 */
function array_zip_keys($arrays, $keys)
{
    $arrays = func_get_args();
    $keys = array_pop($arrays);
    return array_map(function($item) use ($keys) {
        return array_combine($keys, $item);
    }, call_user_func_array('array_zip', $arrays));
}

// ## Miscellaneous

/*
 * Dumps a value using print_r inside a <pre> tag.
 *
 * @param mixed $var     Variable to dump
 * @param mixed $var,... Unlimited optional variables to dump
 */
function dump($var)
{
    foreach (func_get_args() as $var) {
        echo '<pre>';
        print_r($var);
        echo '</pre>';
    }
}

/*
 * Removes files and directories recursively.
 *
 * @param string $path File or directory path
 *
 * @return bool Boolean true on success, false otherwise
 */
function remove($path)
{
    if (is_file($path) || is_link($path)) {
        unlink($path);
    } elseif (is_dir($path)) {
        $objects = scandir($path);
        foreach ($objects as $object) {
            if ($object != '.' && $object != '..') {
                remove($path . '/' . $object);
            }
        }
        reset($objects);
        rmdir($path);
    }
}

/*
 * Forces the download of a file to the client.
 *
 * @param string $filename Filename
 * @param string $content  Content to stream; defaults to null
 *
 * @return bool Boolean true on success, false otherwise
 */
function force_download($filename, $content = null)
{
    if (!headers_sent()) {
        // Required for some browsers
        if (ini_get('zlib.output_compression')) {
            @ini_set('zlib.output_compression', 'Off');
        }

        header('Pragma: public');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');

        // Required for certain browsers
        header('Cache-Control: private', false);

        header('Content-Disposition: attachment; filename="' .
            basename(str_replace('"', '', $filename)) . '";');
        header('Content-Type: application/force-download');
        header('Content-Transfer-Encoding: binary');

        if (isset($content)) {
            header('Content-Length: ' . strlen($content));
            while(ob_get_level()) {
                ob_end_clean();
            }
            echo $content;
        }

        return true;
    } else {
        return false;
    }
}

/*
 * Streams a file to the client.
 *
 * @param string $filename Filename
 * @param string $content  Content to stream; defaults to null
 * @param int    $count    Number of bytes sent (optional)
 *
 * @return bool Boolean true on success, false otherwise
 */
function stream_file($path, $chunks = 4096, &$count = 0)
{
    $file = fopen($path, 'rb');
    if (!$file) return false;
    while (!feof($file)) {
        echo ($buffer = fread($file, $chunks));
        flush();
        $count += strlen($buffer);
    }
    fclose($file);
    return true;
}

/*
 * Forces the client to not cache the response.
 *
 * @return bool
 */
function prevent_cache()
{
    if (!headers_sent()) {
        header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
        header('Cache-Control: no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        return true;
    } else {
        return false;
    }
}

/*
 * Returns the hash of a string using bcrypt.
 *
 * @param string $string      Original string
 * @param int    $work_factor Work factor; defaults to 8
 *
 * @return string
 */
function bcrypt_hash($string, $work_factor = 8)
{
    if (!function_exists('openssl_random_pseudo_bytes')) {
        throw new \RuntimeException('bcrypt_hash() requires openssl extension');
    }

    if ($work_factor < 4 || $work_factor > 31) $work_factor = 8;

    $salt = '$2a$' . str_pad($work_factor, 2, '0', STR_PAD_LEFT) . '$' .
        substr(strtr(base64_encode(openssl_random_pseudo_bytes(16)), '+', '.'),
            0, 22);

    return crypt($string, $salt);
}

/*
 * Determines whether a given string corresponds to a bcrypt-hashed string.
 *
 * @param string $string String to check
 * @param string $hash   bcrypt-hashed string to compare against
 *
 * @return bool Boolean true if matches, false otherwise
 */
function bcrypt_verify($string, $hash)
{
    return crypt($string, $hash) == $hash;
}

/*
 * Returns a slug string, consisting of only alphanumeric words separated by
 * dashes, from any string.
 *
 * @param string $string  Input string
 * @param string $charset Input string character set, defaults to UTF-8
 *
 * @return string
 */
function slugify($string, $charset = 'UTF-8')
{
    $ascii = iconv($charset, 'ASCII//TRANSLIT//IGNORE', $string);
    return preg_replace(array('/[^a-z0-9 ]+/i', '/\s+/'), array('', '-'),
        strtolower($ascii));
}

/*
 * Returns a random string based on length and user-friendliness.
 *
 * @param int  $length          Random string length
 * @param bool $human_friendly  Exclude confusing characters; defaults to true
 * @param bool $include_symbols Include symbols; defaults to false
 * @param bool $unique_chars    Return unique chars; defaults to false
 *
 * @return string
 */
function random_string($length, $human_friendly = true,
    $include_symbols = false, $unique_chars = false)
{
    $nice_chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefhjkmnprstuvwxyz23456789';
    $all_an  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
    $symbols = '!@#$%^&*()~_-=+{}[]|:;<>,.?/"\'\\`';
    $string  = '';

    if ($human_friendly) {
        $pool = $nice_chars;
    } else {
        $pool = $all_an;
        if ($include_symbols) {
            $pool .= $symbols;
        }
    }

    if ($unique_chars && strlen($pool) < $length) {
        throw new \LengthException(
            '$length exceeds the size of the pool and $unique_chars is enabled'
        );
    }

    $pool = str_split($pool);
    shuffle($pool);

    for ($i = 0; $i < $length; $i++) {
        if ($unique_chars) {
            $string .= array_shift($pool);
        } else {
            $string .= $pool[0];
            shuffle($pool);
        }
    }

    return $string;
}

