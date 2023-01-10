<?php

echo User::make()->create("vasya4242", "Тестов Василий Василиевич", "amazingpassword");
//echo User::make()->changePassword('vasya', 'betterpassword');

class Constants
{
    /* Доступ к API */
    const API_URL = '<адрес>'; // адрес панели ispmanager
    const API_LOGIN = '<логин>'; // логин от панели
    const API_PASSWORD = '<пароль>'; // пароль от панели

    /* Генерация случайного пароля */
    const PW_GEN_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; // символы, из которых генерируется случайный пароль
    const PW_GEN_LENGTH = 12; // длинна генерируемого пароля по умолчанию

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
    protected $authLogin;
    protected $authPassword;

    public function __construct(string $func, array $params, bool $authorize = true, ?string $authLogin = null, ?string $authPassword = null)
    {
        $this->func = $func;
        $this->params = $params;
        $this->authorize = $authorize;
        if ($this->authorize) {
            $this->authLogin = $authLogin;
            $this->authPassword = $authPassword;
        }
    }

    public static function make(string $func, array $params, bool $authorize = true, ?string $authLogin = null, ?string $authPassword = null): Connector
    {
        return new static($func, $params, $authorize, $authLogin, $authPassword);
    }

    public function connect()
    {
        $url = sprintf("%s/ispmgr?out=json&func=%s&%s", Constants::API_URL, $this->func, implode('&' , $this->params));

        if ($this->authorize) {
            $authKey = Auth::make($this->authLogin, $this->authPassword)->getKey();
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
    private $apiLogin;
    private $apiPassword;

    public function __construct(?string $apiLogin, ?string $apiPassword)
    {
        $this->apiLogin = $apiLogin;
        $this->apiPassword = $apiPassword;
    }

    public static function make(?string $apiLogin, ?string $apiPassword): Auth
    {
        return new static($apiLogin, $apiPassword);
    }

    /**
     * @throws Exception
     */
    public function getKey()
    {
        $response = Connector::make('auth', [
            'username=' . $this->apiLogin,
            'password=' . $this->apiPassword
        ], false)->connect();

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
    protected $apiLogin;
    protected $apiPassword;

    public function __construct(string $apiLogin = Constants::API_PASSWORD, string $apiPassword = Constants::API_PASSWORD)
    {
        $this->apiLogin = $apiLogin;
        $this->apiPassword = $apiPassword;
    }

    public static function make($apiLogin = Constants::API_LOGIN, $apiPassword = Constants::API_PASSWORD): BaseApiMethod
    {
        return new static($apiLogin, $apiPassword);
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
        if (!$password)
            $password = Credentials::generatePassword();

        $response = Connector::make('user.add.finish', [
            'addinfo=off',
            'sok=ok',
            'name=' . $login,
            'fullname=' . $name,
            'passwd=' . $password,
            'confirm=' . $password
        ], true, $this->apiLogin, $this->apiPassword)->connect();

        if (!is_array($response)) {
            $r = json_decode($response, true);

            if ($r['doc']) {
                if ($r['doc']['error']) {
                    return json_encode([
                        'status' => Constants::API_ERROR_STATUS,
                        'response' => $r,
                    ]);
                } else {
                    return json_encode([
                        'status' => Constants::OK_STATUS,
                        'login' => $login,
                        'password' => $password,
                    ]);
                }
            }
        } else {
            return json_encode($response);
        }

        return json_encode([
            'status' => Constants::UNKNOWN_ERROR_STATUS
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
            'name=' . $login,
            'elid=' . $login,
            'passwd=' . $password,
            'confirm=' . $password
        ], true, $this->apiLogin, $this->apiPassword)->connect();

        if (!is_array($response)) {
            $r = json_decode($response, true);

            if ($r['doc']['error']) {
                return json_encode([
                    'status' => Constants::API_ERROR_STATUS,
                    'response' => $r,
                ]);
            } else {
                return json_encode([
                    'status' => Constants::OK_STATUS,
                    'name' => $login,
                    'password' => $password,
                ]);
            }
        } else {
            return json_encode($response);
        }
    }
}

