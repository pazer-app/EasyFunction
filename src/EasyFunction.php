<?php declare(strict_types=1);
namespace PazerApp\EasyFunction;
use Error;
use Exception;
class EasyFunction {
    public function passwordHash(string $password) : string { return password_hash($password, PASSWORD_DEFAULT) ?? ""; }
    public function jsonEnc(array $array) : string { return json_encode($array, JSON_UNESCAPED_UNICODE) ?? "{}"; }
    public function jsonDec(string $json) : array { return json_decode($json, true) ?? array(); }
    public function securityEnc(string $str, string $private_key, string $public_key) : string {
        try {
            $key = hash('sha256', $private_key); $iv = substr(hash('sha256', $public_key), 0, 16);
            return str_replace("=", "", base64_encode(openssl_encrypt($str, "AES-256-CBC", $key, 0, $iv))) ?? "";
        } catch (Error $e){ return ""; }
    }
    public function securityDec(string $str, string $private_key, string $public_key) : string {
        try {
            $key = hash('sha256', $private_key); $iv = substr(hash('sha256', $public_key), 0, 16);
            return openssl_decrypt(base64_decode($str), "AES-256-CBC", $key, 0, $iv);
        } catch (Error $e){ return ""; }
    }
    public function setCookie(string $name, $value, string $domain, int $time = 3600, string $path = "/", bool $secure = true, bool $httponly = true) : void {
        setcookie($name, $value, ['expires' => time() + $time, 'path' => $path, 'domain' => $domain, 'secure' => $secure, 'httponly' => $httponly]);
    }
    public function clearCookie(string $name, string $domain, string $path = "/", bool $secure = true, bool $httponly = true) : void {
        setcookie($name, "", ['expires' => time() - 3600, 'path' => $path, 'domain' => $domain, 'secure' => $secure, 'httponly' => $httponly]);
    }
    public function randIntString(int $length = 10) : string { $characters = '0123456789'; return $this->_randomString($characters, $length); }
    public function randIntStringNoneZero(int $length = 10) : string { $num = $this->randIntString($length); if($num[0] === "0") { $num[0] = $this->randInt(1,9); } return $num; }
    public function randString(int $length = 10) : string { $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; return $this->_randomString($characters, $length); }
    public function randMixedString(int $length = 10) : string { $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; return $this->_randomString($characters, $length); }
    public function randInt(int $min, int $max = PHP_INT_MAX) : int { return mt_rand($min, $max); }
    protected function _randomString(string $charset, int $length = 10) : string {
        $charactersLength = strlen($charset); $randomString = '';
        for ($i = 0; $i < $length; $i++) try { $randomString .= $charset[random_int(0, $charactersLength - 1)]; } catch (Exception $e) { $randomString = ""; } return $randomString;
    }
    public function genID(int $addLength = 0) : string { return base64_encode($this->randMixedString(8).time().$this->randMixedString(14 + $addLength)); }
    public function arraySecEnc(array $array, string $private_key, string $public_key) : string { return $this->securityEnc(json_encode($array, JSON_UNESCAPED_UNICODE), $private_key, $public_key); }
    public function arraySecDEc(string $ssid, string $private_key, string $public_key) : array { return json_decode($this->securityDec($ssid,$private_key, $public_key), true) ?? array(); }
    public function location(string $url) : void { header("Location: {$url}"); exit; }
    public function headerJSON() : void { header('Content-Type: application/json; charset=utf-8'); }
    public function displayErrorLog() : void { ini_set('display_errors', "1"); }
}
