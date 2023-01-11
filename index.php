<?php

//echo User::make()->create("vasya4242", "Тестов Василий Василиевич", "amazingpassword");
//echo User::make()->changePassword('vasya4242', 'betterpassword');
echo DB::make()->create("myDB2", "www-root");

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
            return [
                'status' => 'auth curl error',
                'message' => curl_error($this->ch)
            ];
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

            if ($r['doc']) {
                if ($r['doc']['error']) {
                    return [
                        'status' => Constants::AUTH_API_ERROR_STATUS,
                        'response' => $r,
                    ];
                } else if ($r['doc']['auth']) {
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

class ResponseChecker
{
    public static function check($response, $okParams = [], $type = 1)
    {
        switch ($type) {
            case 1: return self::check1Type($response, $okParams);
            case 2: return self::check2Type($response, $okParams);
        }
    }

    private static function check1Type($response, $okParams)
    {
        if (!is_array($response)) {
            $r = json_decode($response, true);

            if ($r['doc']) {
                if ($r['doc']['error']) {
                    return json_encode([
                        'status' => Constants::API_ERROR_STATUS,
                        'response' => $r,
                    ]);
                } else {
                    return json_encode(array_merge([
                        'status' => Constants::OK_STATUS,
                    ], $okParams));
                }
            }
        } else {
            return json_encode($response);
        }

        return json_encode([
            'status' => Constants::UNKNOWN_ERROR_STATUS
        ]);
    }

    private static function check2Type($response, $okParams)
    {
        if (!is_array($response)) {
            $r = json_decode($response, true);

            if ($r['doc']['error']) {
                return json_encode([
                    'status' => Constants::API_ERROR_STATUS,
                    'response' => $r,
                ]);
            } else {
                return json_encode(array_merge([
                    'status' => Constants::OK_STATUS,
                ], $okParams));
            }
        } else {
            return json_encode($response);
        }
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

        return ResponseChecker::check($response, [
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

        return ResponseChecker::check($response, [
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

        return ResponseChecker::check($response, [
            'db' => $name,
            'username' => $username,
            'password' => $password,
        ]);
    }
}