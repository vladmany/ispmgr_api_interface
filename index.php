<?php

class Constants
{
    /* Доступ к API */
    const API_URL = '<адрес>'; // адрес панели ispmanager
    const API_LOGIN = '<логин>'; // логин от панели
    const API_PASSWORD = '<пароль>'; // пароль от панели

    /* Генерация случайного пароля */
    const PW_GEN_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; // символы, из которых генерируется случайный пароль
    const PW_GEN_LENGTH = 12; // длинна генерируемого пароля по умолчанию

    /* Базы данных */
    const DB_DEFAULT_CHARSET = 'utf8mb4';

    /* Статусы ответов */
    const OK_STATUS = 'ok'; // успешное выполнение запроса
    const API_ERROR_STATUS = 'api_error'; // внутренняя ошибка ispmanager
    const CURL_ERROR_STATUS = 'curl_error'; // сетевая ошибка запроса к адресу
    const AUTH_API_ERROR_STATUS = 'auth_api_error'; // внутренняя ошибка ispmanager при авторизации
    const AUTH_CURL_ERROR_STATUS = 'auth_curl_error'; // сетевая ошибка запроса к адресу при авторизации
    const UNKNOWN_ERROR_STATUS = 'unknown_error'; // неизвестная ошибка
}

class Connector
{
    protected $ch;
    protected $func;
    protected $params;
    protected $authorize;
    protected $apiUrl;
    protected $apiLogin;
    protected $apiPassword;

    public function __construct(string $func, array $params, bool $authorize = true, ?string $apiUrl = null, ?string $apiLogin = null, ?string $apiPassword = null)
    {
        $this->func = $func;
        $this->params = $params;
        $this->authorize = $authorize;
        $this->apiUrl = $apiUrl;
        if ($this->authorize) {
            $this->apiLogin = $apiLogin;
            $this->apiPassword = $apiPassword;
        }
    }

    public static function make(string $func, array $params, bool $authorize = true, ?string $apiUrl = null, ?string $apiLogin = null, ?string $apiPassword = null): Connector
    {
        return new static($func, $params, $authorize, $apiUrl, $apiLogin, $apiPassword);
    }

    public function connect()
    {
        $url = sprintf("%s/ispmgr?out=json&func=%s&%s", $this->apiUrl, $this->func, implode('&' , $this->params));

        if ($this->authorize) {
            $authKey = Auth::make($this->apiUrl, $this->apiLogin, $this->apiPassword)->getKey();
            if (is_array($authKey)) {
                return $authKey; // возвращаем ошибку
            }

            $url .= '&auth=' . $authKey;
        }

        $this->ch = curl_init($url);

        $this->setOpt();

        $response = curl_exec($this->ch);

        if (curl_errno($this->ch)) {
            $status = ($this->func == 'auth') ? Constants::AUTH_CURL_ERROR_STATUS : Constants::CURL_ERROR_STATUS;

            return Response::create($status, ['message' => curl_error($this->ch)], false);
        }

        curl_close($this->ch);

        return $response;
    }

    protected function setOpt()
    {
        curl_setopt($this->ch, CURLOPT_HEADER, false);
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($this->ch, CURLOPT_ENCODING, '');
    }
}

class Auth
{
    private $apiUrl;
    private $apiLogin;
    private $apiPassword;

    public function __construct(?string $apiUrl, ?string $apiLogin, ?string $apiPassword)
    {
        $this->apiUrl = $apiUrl;
        $this->apiLogin = $apiLogin;
        $this->apiPassword = $apiPassword;
    }

    public static function make(?string $apiUrl, ?string $apiLogin, ?string $apiPassword): Auth
    {
        return new static($apiUrl, $apiLogin, $apiPassword);
    }

    /**
     * @throws Exception
     */
    public function getKey()
    {
        $response = Connector::make('auth', [
            'username=' . $this->apiLogin,
            'password=' . $this->apiPassword
        ], false, $this->apiUrl)->connect();

        if(!is_array($response)) {
            $r = json_decode($response, true);

            if (array_key_exists('doc', $r)) {
                if (array_key_exists('error', $r['doc'])) {
                    return [
                        'status' => Constants::AUTH_API_ERROR_STATUS,
                        'response' => $r,
                    ];
                } else if (array_key_exists('auth', $r['doc'])) {
                    return $r['doc']['auth']['$id'];
                }
            }
        } else {
            return json_encode($response);
        }

        return [
            'status' => Constants::UNKNOWN_ERROR_STATUS
        ];
    }
}

class Credentials
{
    public static function generatePassword($length = Constants::PW_GEN_LENGTH) {
        $chars = Constants::PW_GEN_CHARS;

        return substr(str_shuffle(str_repeat($chars,$length)),0,$length);
    }
}

abstract class BaseApiMethod
{
    protected $apiUrl;
    protected $apiLogin;
    protected $apiPassword;

    public function __construct(string $apiUrl = Constants::API_URL, string $apiLogin = Constants::API_PASSWORD, string $apiPassword = Constants::API_PASSWORD)
    {
        $this->apiUrl = $apiUrl;
        $this->apiLogin = $apiLogin;
        $this->apiPassword = $apiPassword;
    }

    public static function make($apiUrl = Constants::API_URL, $apiLogin = Constants::API_LOGIN, $apiPassword = Constants::API_PASSWORD): BaseApiMethod
    {
        return new static($apiUrl, $apiLogin, $apiPassword);
    }
}

class Response
{
    public static function check($response, $okParams = [], $type = 1, $encodeJSON = true)
    {
        switch ($type) {
            case 1: return self::check1Type($response, $okParams, $encodeJSON);
            case 2: return self::check2Type($response, $okParams, $encodeJSON);
        }
    }

    private static function check1Type($response, $okParams, $encodeJSON)
    {
        if (!is_array($response)) {
            $r = json_decode($response, true);

            if (array_key_exists('doc', $r)) {
                if (array_key_exists('error', $r['doc'])) {
                    return self::create(Constants::API_ERROR_STATUS, ['response' => $r], $encodeJSON);
                } else {
                    return self::create(Constants::OK_STATUS, $okParams, $encodeJSON);
                }
            }
        } else {
            return $response;
        }

        return self::create(Constants::UNKNOWN_ERROR_STATUS, [], $encodeJSON);
    }

    private static function check2Type($response, $okParams, $encodeJSON)
    {
        if (!is_array($response)) {
            $r = json_decode($response, true);

            if (array_key_exists('doc', $r) && array_key_exists('error', $r['doc'])) {
                return self::create(Constants::API_ERROR_STATUS, ['response' => $r]);
            } else {
                return self::create(Constants::OK_STATUS, $okParams);
            }
        } else {
            return $response;
        }
    }

    public static function create($status, $addParams = [], $encodeJSON = true)
    {
        $response = array_merge([
            'status' => $status
        ], $addParams);

        return $encodeJSON ? json_encode($response) : $response;
    }
}

class User extends BaseApiMethod
{
    /**
     * @param $login - логин
     * @param $name - ФИО
     * @param null $password - пароль (можно оставить пустым, пароль сгенерируется автоматически)
     * @return bool|string
     */
    public function create($login, $name, $password = null)
    {
        $password = !$password ? Credentials::generatePassword() : $password;

        $response = Connector::make('user.add.finish', [
            'addinfo=off',
            'sok=ok',
            'name=' . $login,
            'fullname=' . $name,
            'passwd=' . $password,
            'confirm=' . $password
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'login' => $login,
            'password' => $password
        ]);
    }

    /**
     * @param $login - логин
     * @param $password - новый пароль
     * @return false|string
     */
    public function changePassword($login, $password)
    {
        $response = Connector::make('user.edit', [
            'sok=ok',
            'login=' . $login,
            'elid=' . $login,
            'passwd=' . $password,
            'confirm=' . $password
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'login' => $login,
            'password' => $password
        ], 2);
    }
}

class DB extends BaseApiMethod
{
    public function create($name, $owner, $username = null, $password = null, $charset = Constants::DB_DEFAULT_CHARSET)
    {
        $username = !$username ? $owner : $username;
        $password = !$password ? Credentials::generatePassword() : $password;

        $response = Connector::make('db.edit', [
            'name=' . $name,
            'owner=' . $owner,
            'server=MySQL',
            'charset=' . $charset,
            'username=' . $username,
            'password=' . $password,
            'confirm=' . $password,
            'sok=ok'
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'db' => $name,
            'username' => $username,
            'password' => $password,
        ]);
    }
}

class Site extends BaseApiMethod
{
    public function create($name, $owner, $home = null)
    {
        $home = !$home ? ('www/' . $name) : $home;

        $response = Connector::make('site.edit', [
            'site_name=' . $name,
            'site_owner=' . $owner,
            'site_home=www/' . $name . $home,
            'sok=ok'
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'name' => $name,
            'home' => $home
        ]);
    }
}

class File extends BaseApiMethod
{
    public function copy($fromUser, $fromSite, $filePath, $toUser, $toSite, $toPath = '')
    {
        $fileName = basename($filePath);
        $dir = str_replace($fileName, '', $filePath);

        $absoluteDestPath = 'var/www/' . $toUser . '/data/www/' . $toSite . '/' . trim($toPath, '/');
        $dirHex = bin2hex($absoluteDestPath);

        $response = Connector::make('file.copyto', [
            'elname=' . $fileName,
            'elid=' . $fileName,
            'plid=/var/www/' . $fromUser . '/data/www/' . $fromSite . '/' . $dir,
            'dirlist=' . $dirHex,
            'sok=ok'
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'path' => $absoluteDestPath . '/' . $fileName
        ]);
    }

    public function unzip($user, $site, $filePath, $toUser = null, $toSite = null, $toPath = '')
    {
        $fileName = basename($filePath);
        $dir = str_replace($fileName, '', $filePath);

        $absoluteDestPath = 'var/www/';
        if ($toUser && $toSite)
            $absoluteDestPath .= $toUser . '/data/www/' . $toSite . '/' . trim($toPath, '/');
        else
            $absoluteDestPath .= $user . '/data/www/' . $site . trim($dir, '/');

        $dirHex = bin2hex($absoluteDestPath);

        $response = Connector::make('file.extract', [
            'elname=' . $fileName,
            'elid=' . $fileName,
            'plid=/var/www/' . $user . '/data/www/' . $site . '/' . trim($dir, '/'),
            'dirlist=' . $dirHex,
            'newdir=',
            'sok=ok'
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'path' => $absoluteDestPath . '/'
        ]);
    }

    public function changeOwner($user, $site, $path, $newOwner)
    {
        $path = trim($path, '/');
        $pathChunks = explode('/', $path);
        $lastIndex = count($pathChunks) - 1;
        $itemName = $pathChunks[$lastIndex];
        array_splice($pathChunks, $lastIndex);
        $itemPath = '/var/www/' . $user . '/data/www/' . $site . '/' . implode('/', $pathChunks);

        $response = Connector::make('file.unixattr', [
            'elid=' . $itemName,
            'plid=' . $itemPath,
            'uid=' . $user,
            'gid=' . $user,
            'recursive=rowner',
            'mode=644',
            'sok=ok'
        ], true, $this->apiUrl, $this->apiLogin, $this->apiPassword)->connect();

        return Response::check($response, [
            'path' => $itemPath . '/' . $itemName
        ]);
    }
}