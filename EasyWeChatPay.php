<?php

/**
 * @author huajiao238
 * @link https://github.com/huajiao238
 */

class EasyWeChatPay
{
    private string $mchid;
    private string $appid;
    private string $cert_url = "https://api.mch.weixin.qq.com/v3/certificates";
    private int $time_stamp;
    private array $params;
    private string $serial_no;
    private string $keyPath;
    private string $nonceStr;
    private string $scheme = "WECHATPAY2-SHA256-RSA2048";
    private string $apikey;
    private array $url = [
        "pc" => "https://api.mch.weixin.qq.com/v3/pay/transactions/native",
        "h5" => "https://api.mch.weixin.qq.com/v3/pay/transactions/h5",
        "jsapi" => "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi",
        "miniapp" => "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi",
        "app" => "https://api.mch.weixin.qq.com/v3/pay/transactions/app"
    ];
    private string $type = "pc";
    private string $openId;
    private string $secret;


    public function __construct()
    {
        $this->time_stamp = time();
        $this->createNonceStr();
    }

    /**
     * 设置请求体
     * @param array $params 请求体
     * @return $this
     */
    public function setParams(array $params): EasyWeChatPay
    {
        $this->params = $params;
        return $this;
    }

    /**
     * 设置商户号
     * @param string $mchid 商户号  在商户平台->产品中心->开发配置中可查看
     * @return $this
     */
    public function setMchid(string $mchid): EasyWeChatPay
    {
        $this->mchid = $mchid;
        return $this;
    }


    /**
     * 设置APPID
     * @param string $appid 微信开发平台的应用APPID或公众号APPID都可以
     * @return $this
     */
    public function setAppid(string $appid): EasyWeChatPay
    {
        $this->appid = $appid;
        return $this;
    }

    /**
     * 设置证书序列号
     * @param string $serial_no 证书序列号  可在商户平台->账户中心->API安全->申请API证书中查看
     * @return $this
     */
    public function setSerialNo(string $serial_no): EasyWeChatPay
    {
        $this->serial_no = $serial_no;
        return $this;
    }

    /**
     * 设置私钥路径
     * @param string $key_path 私钥路径
     * @return $this
     * @throws ErrorException
     */
    public function setKeyPath(string $key_path): EasyWeChatPay
    {
        if (!file_exists($key_path)) {
            throw new ErrorException("私钥2文件不存在");
        }
        $this->keyPath = $key_path;
        return $this;
    }

    /**
     * 设置apikey  在商户平台->账户中心->API安全->设置APIV3秘钥
     * @param string $apikey 在商户平台->账户中心->API安全->设置APIV3秘钥
     * @return $this
     */
    public function setApiKey(string $apikey): EasyWeChatPay
    {
        $this->apikey = $apikey;
        return $this;
    }

    /**
     * 设置支付类型
     * @param string $type 支付类型  pc/h5/app/jsapi
     * @return $this
     * @throws ErrorException
     */
    public function setType(string $type): EasyWeChatPay
    {
        if (!array_key_exists($type, $this->url)) {
            throw new ErrorException("不支持的支付类型");
        }
        $this->type = $type;
        return $this;
    }

    /**
     * 设置openID
     * @param string $openid
     * @return $this
     */
    public function setOpenId(string $openid): EasyWeChatPay
    {
        $this->openId = $openid;
        return $this;
    }

    /**
     * @param string $secret
     * @return EasyWeChatPay
     * @throws ErrorException
     */
    public function setSecret(string $secret): EasyWeChatPay
    {
        if ("" === $secret) {
            throw new ErrorException("请设置公众号私钥");
        }
        $this->secret = $secret;
        return $this;
    }

    /**
     * 发起支付
     * @return array
     */
    public function doPayment(): array
    {
        if (!array_key_exists("appid", $this->params)) {
            $this->params["appid"] = $this->appid;
        } else {
            $this->appid = $this->params["appid"];
        }
        if (!array_key_exists("mchid", $this->params)) {
            $this->params["mchid"] = $this->mchid;
        } else {
            $this->mchid = $this->params["mchid"];
        }
        if ($this->type == "jsapi" || $this->type == "miniapp") {
            $this->params["payer"]["openid"] = $this->openId;
        }
        if ($this->type == "h5") {
            $this->params["scene_info"]["payer_client_ip"] = $_SERVER["REMOTE_ADDR"];
        }
        $this->params["amount"]["total"] = (float)$this->params["amount"]["total"] * 100;
        return match ($this->type) {
            "pc", "h5" => $this->requestPost($this->params),
            "jsapi", "app", "miniapp"=> $this->buildJsApiBody($this->params)
        };
    }

    /**
     * @return void
     * @throws ErrorException
     */
    public function getOpenId(): void
    {
        if (!isset($_GET["code"])) {
            header("location:{$this->getWeChatCodeUrl()}");
            exit();
        } else {
            $code = $_GET["code"];
            $result = file_get_contents($this->buildGetOpenIdUrl($code));
            $result = json_decode(json_encode($result), true);
            if (array_key_exists("openid", $result)) {
                $this->openId = $result["openid"];
            }else {
                throw new ErrorException($result["errmsg"]);
            }
        }
    }

    /**
     * 异步验签
     * @throws ErrorException
     * @return bool
     */
    public function checkSign(): bool {
        if(!this->privateKey) {
            throw new ErrorException("请设置私钥路径");
        }
        if(!$this->apiKey) {
            throw new ErrorException("请设置apiv3key");
        }
        $wechat_sign = $_SERVER["HTTP_Wechatpay-Signature"];
        $wechat_serial_no = $_SERVER["HTTP_Wechatpay-Serial"];
        $timestamp = $_SERVER["HTTP_Wechatpay-Timestamp"];
        $nonce = $_SERVER["HTTP_Wechatpay-Nonce"];
        $data = file_get_contents("php://input");
        $data = (array)json_decode($data, true);
        $nonce_str = $data["resource"]["nonce"];
        $associated_data = $data["resource"]["associated_data"];
        $cipher_text = $data["resource"]["ciphertext"];
        try {
            $result = $this->notifyBodyDecrypt($cipher_text, $nonce_str, $associated_data);
        } catch (ErrorException $e) {
            throw new ErrorException($e->getMessage());
        }
        $resultJson = json_encode($result);
        $platform_public_key = $this->getPlatformCertificates($wechat_serial_no);
        $origin_sign = "$timestamp\n$nonce\n$resultJson";
        return $this->signVerify($origin_sign, $wechat_sign, $platform_public_key);
    }

    /**
     * 通知消息体解密
     * @param string $cipherText
     * @param string $nonce
     * @param string $a_data
     * @param string $type
     * @return array|false|string
     * @throws ErrorException
     */
    public function notifyBodyDecrypt(string $cipherText, string $nonce, string $a_data, string $type = ""): bool|array|string
    {
        try {
            $data = sodium_crypto_aead_aes256gcm_decrypt($cipherText, $a_data, $nonce, $this->apikey);
        } catch (SodiumException $e) {
            throw new ErrorException($e->getMessage());
        }
        return $type == "" ? (array)json_decode($data, true) : $data;
    }

    /**
     * 构造jsapi体
     * @param array $param
     * @return bool|string
     */
    private function buildJsApiBody(array $param): bool|string
    {
        $result = $this->requestPost($param);
        if ($result["code"] == 200) {
            $prepay_id = $result["message"]["prepay_id"];
        } else {
            return $result["code"];
        }
        $sign = $this->buildJSApiSignParam($prepay_id);
        if($this->type == "app") {
            $body = [
                "appid" => $this->appid,
                "partnerid" =>  $this->mchid,
                "timestamp" => $this->time_stamp,
                "noncestr" => $this->nonceStr,
                "prepayid" => $prepay_id,
                "package"   =>  "Sign=WXPay",
                "sign" => $sign
            ];
        }else {
            $body = [
                "appId" => $this->appid,
                "timeStamp" => $this->time_stamp,
                "nonceStr" => $this->nonceStr,
                "package" => "prepay_id=" . $prepay_id,
                "signType" => "RSA",
                "paySign" => $sign
            ];
        }
        if($this->type == "miniapp") {
            unset($body["appId"]);
        }
        return json_encode($body);
    }

    /**
     *获取code地址
     * @return string
     */
    private function getWeChatCodeUrl(): string
    {
        $request_body = [
            "appid" => $this->appid,
            "redirect_url" => $_SERVER["REQUEST_SCHEME"]."://".$_SERVER["HTTP_HOST"].$_SERVER["REQUEST_URI"],
            "response_type" => "code",
            "scope" => "snsapi_base"
        ];
        return "https://open.weixin.qq.com/connect/oauth2/authorize?" . http_build_query($request_body) . "#wechat_redirect";
    }

    /**
     * 获取openID地址
     * @param string $code
     * @throws ErrorException
     * @return string
     */
    private function buildGetOpenIdUrl(string $code): string
    {
        if(!$this->secret) {
            throw new ErrorException("请先设置公众号私钥");
        }
        $param = [
            "appid" => $this->appid,
            "secret" => $this->secret,
            "code" => $code,
            "grant_type" => "authorization_code"
        ];
        return "https://api.weixin.qq.com/sns/oauth2/access_token?" . http_build_query($param);
    }

    /**
     * 获取请求路径
     * @param string $url 请求地址
     * @return string
     */
    private function getHostPath(string $url): string
    {
        $url = parse_url($url);
        return $url["path"];
    }

    /**
     * 获取协议头
     * @param string $url 请求地址
     * @return string
     */
    private function getHostScheme(string $url): string
    {
        $url = parse_url($url);
        return $url["scheme"];
    }

    /**
     * 生成随机字符串
     * @param int $length 字符串长度
     * @return void
     */
    private function createNonceStr(int $length = 16): void
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $str = '';
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        $this->nonceStr = $str;
    }

    /**
     * 获取私钥
     */
    private function getPrivateKey(): OpenSSLAsymmetricKey|bool
    {
        return openssl_get_privatekey(file_get_contents($this->keyPath));
    }

    /**
     * 生成签名
     * @param string $request_body 请求体
     * @param string $method 请求头
     * @return string
     */
    private function signParamsGenerate(string $request_body, string $method = "POST"): string
    {
        $host_path = $method == "POST" ? $this->getHostPath($this->url[$this->type]) : $this->getHostPath($this->cert_url);
        $sign_origin = "$method\n$host_path\n$this->time_stamp\n$this->nonceStr\n$request_body\n";
        openssl_sign($sign_origin, $sign, $this->getPrivateKey(), 'sha256WithRSAEncryption');
        return base64_encode($sign);
    }

    /**
     * jsapi加签
     * @param string $prepay_id
     * @return string
     */
    private function buildJSApiSignParam(string $prepay_id): string
    {
        $origin_sign = "$this->type == 'miniapp' ? '': $this->appid\n"."$this->time_stamp\n$this->nonceStr\n" . $this->type == 'app' ? $prepay_id : 'prepay_id=' . "$prepay_id}\n";
        openssl_sign($origin_sign, $sign, $this->getPrivateKey(), 'sha256WithRSAEncryption');
        return base64_encode($sign);
    }

    /**
     * 拼接请求头参数
     * @param string $request_body 请求体
     * @param string $method 请求方法
     * @return string
     */
    private function getAuthorizationHeadParam(string $request_body = "", string $method = "POST"): string
    {
        return sprintf('mchid="%s",serial_no="%s",nonce_str="%s",timestamp="%s",signature="%s"', $this->mchid, $this->serial_no, $this->nonceStr, $this->time_stamp, $this->signParamsGenerate($request_body, $method));
    }

    /**
     * 设置Authorization请求头
     * @param array $data
     * @param string $method
     * @return string[]
     */
    private function getAuthorizationHeader(array $data = [], string $method = "POST"): array
    {
        return array(
            "Authorization:" . $this->scheme . " " . $this->getAuthorizationHeadParam($data == [] ? "" : json_encode($data), $method),
            "Content-Type:application/json",
            "Accept:application/json",
            "User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.37"
        );
    }

    /**
     * POST请求
     * @param array $data 请求体
     * @return array
     */
    private function requestPost(array $data): array
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $this->url[$this->type]);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($curl, CURLOPT_HTTPHEADER, $this->getAuthorizationHeader($data));
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        if ($this->getHostScheme($this->url[$this->type]) === "https") {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        }
        $response = curl_exec($curl);
        $response_info = curl_getinfo($curl);
        curl_close($curl);
        $response = json_decode($response);
        if ($response_info["http_code"] !== 200) {
            return [
                "code" => $response_info["http_code"],
                "message" => "错误代码：{$response->code},错误信息：{$response->message}"
            ];
        }
        return [
            "code" => 200,
            "message" => json_decode(json_encode($response), true)
        ];
    }

    /**
     * GET请求
     * @param array $header
     * @return array
     */
    private function requestGet(array $header): array
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $this->cert_url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        if ($this->getHostScheme($this->cert_url) === "https") {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        }
        $response = curl_exec($curl);
        $response_info = curl_getinfo($curl);
        curl_close($curl);
        $response = json_decode($response);
        if ($response_info["http_code"] !== 200) {
            return [
                "code" => $response_info["http_code"],
                "message" => "错误代码：{$response->code},错误信息：{$response->message}"
            ];
        }
        return (array)json_decode($response, true);
    }

    /**
     * 解密 （需要开启sodium扩展）
     * @param $associatedData
     * @param $nonceStr
     * @param $ciphertext
     * @return string
     * @throws ErrorException
     */
    private function decryptToString($associatedData, $nonceStr, $ciphertext): string
    {
        $ciphertext = base64_decode($ciphertext);
        if (!function_exists("sodium_crypto_aead_aes256gcm_decrypt")) {
            throw new ErrorException("请先在php.ini中开启sodium扩展");
        }
        try {
            return sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->apikey);
        } catch (\SodiumException $e) {
            throw new ErrorException($e->getMessage());
        }
    }

    /**
     * 下载平台证书
     * @param string $platformSerialNo
     * @return string
     * @throws ErrorException
     */
    private function getPlatformCertificates(string $platformSerialNo): string {
        $platformCertificates = $this->requestGet($this->buildDownloadPlatformCertificatesHeader());
        $platform_public_key = "";
        if(!array_key_exists("code",$platformCertificates)) {
            foreach ($platformCertificates["data"] as $v) {
                if($v["serial_no"] == $platformSerialNo) {
                    try {
                        $platform_public_key = $this->notifyBodyDecrypt($v["encrypt_certificate"]["cipher"], $v["encrypt_certificate"]["nonce"], $v["encrypt_certificate"]["associated_data"], "1");
                    } catch (ErrorException $e) {
                        throw new ErrorException($e->getMessage());
                    }
                }
            }
        }
        return $platform_public_key;
    }

    /**
     * 构造证书下载请求头
     * @return string[]
     */
    private function buildDownloadPlatformCertificatesHeader(): array {
        return [
            "Authorization:WECHATPAY2-SHA256-RSA2048 {$this->signDownloadPlatformCertificatesAuthorization()}",
            "Accept:application/json",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.37"
        ];
    }

    /**
     * 下载证书加签
     * @return string
     */
    private function signDownloadPlatformCertificatesAuthorization(): string {
        $string = "GET\n/v3/certificates\n$this->time_stamp\n$this->nonceStr\n\n";
        openssl_sign($string, $sign, $this->getPrivateKey(), 'sha256WithRSAEncryption');
        return $sign;
    }

    /**
     * 验证签名
     * @param string $data
     * @param string $sign
     * @param $public_key
     * @return bool
     */
    private function signVerify(string $data, string $sign, $public_key): bool {
        return (1 == openssl_verify($data, base64_decode($sign), openssl_get_publickey($public_key),"sha256WithRSAEncryption"));
    }
}
