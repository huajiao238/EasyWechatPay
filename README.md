## 微信支付APIV3 PHP类库

微信支付APIV3PHP支付类库，支持电脑网页支付、手机H5支付、公众号支付、小程序支付、app支付、异步通知验签，轻轻松松一个类就解决了

PHP版本 >=8

需在php.ini中开启**sodium**扩展

### 调用示例：

#### 一、电脑网页支付：

```php
<?php
require "EasyWeChatPay.php";
$body = [
    "description" => "APIV3网页支付测试",
    "out_trade_no" => date('YmdHis'),
    "notify_url" => "异步通知地址",
    "amount" => [
        "total" => 10,   //金额,单位：元
        'currency' => "CNY"
    ],
    "appid" => "公众号APPID",   //公众号传公众号APPID、小程序传小程序APPID、app传微信开放平台相对应的APPID
    "mchid" => "你的商户号"
];

try {
    $pay = new EasyWeChatPay();
    $pay->setParams($body);
    $pay->setSerialNo("你的V3证书序列号");
    $pay->setKeyPath("证书路径");
    $pay->setType("pc");   //支付方式   电脑网页：pc, 公众号: jsapi, 小程序:miniapp, 手机端：h5，app支付： app
    $result = $pay->doPayment();
    print_r($result);
}catch (ErrorException $e) {
    echo $e->getMessage();
}
```

**成功返回示例：**

```php
[
	"code"	=> 200,
	"message"	=> [
		"code_url"	=>	"weixin://wxpay/bizpayurl?pr=xxxxxxxx"    //将code_url转成二维码展示即可
	]
]
```

#### 二、手机网页支付：

```php
<?php
require "EasyWeChatPay.php";
$body = [
    "description" => "APIV3网页支付测试",
    "out_trade_no" => date('YmdHis'),
    "notify_url" => "异步通知地址",
    "amount" => [
        "total" => 10,   //金额,单位：元
        'currency' => "CNY"
    ],
    "appid" => "公众号APPID",   //公众号传公众号APPID、小程序传小程序APPID、app传微信开放平台相对应的APPID
    "mchid" => "你的商户号"
];

try {
    $pay = new EasyWeChatPay();
    $pay->setParams($body);
    $pay->setSerialNo("你的V3证书序列号");
    $pay->setKeyPath("证书路径");
    $pay->setType("h5");   //支付方式   电脑网页：pc, 公众号: jsapi, 小程序:miniapp, 手机端：h5，app支付： app
    $result = $pay->doPayment();
    print_r($result);
}catch (ErrorException $e) {
    echo $e->getMessage();
}
```

**成功返回示例：**

```php
[
	"code"	=> 200,
	"message"	=> [
		"h5_url"	=>	"https://wx.tenpay.com/cgi-bin/mmpayweb-bin/checkmweb?prepay_id=xxxxx"
	]
]
//跳转到h5_url即可
```

#### 三、公众号支付：

```php
<?php
require "EasyWeChatPay.php";
$body = [
    "description" => "APIV3网页支付测试",
    "out_trade_no" => date('YmdHis'),
    "notify_url" => "异步通知地址",
    "amount" => [
        "total" => 10,   //金额,单位：元
        'currency' => "CNY"
    ],
    "appid" => "公众号APPID",   //公众号传公众号APPID、小程序传小程序APPID、app传微信开放平台相对应的APPID
    "mchid" => "你的商户号"
];

try {
    $pay = new EasyWeChatPay();
    $pay->getOpenId();  //获取openID
    $pay->setParams($body);
    $pay->setSerialNo("你的V3证书序列号");
    $pay->setKeyPath("证书路径");
    $pay->setType("jsapi");   //支付方式   电脑网页：pc, 公众号: jsapi, 小程序:miniapp, 手机端：h5，app支付： app
    $result = $pay->doPayment();
    print_r($result);
}catch (ErrorException $e) {
    echo $e->getMessage();
}
```

**成功返回示例：**

```json
{
	"appId": "wxxxxxxxxx",
	"timeStamp": "XXXXXXX",
	"nonceStr": "xxxxxxxx",
	"package": "prepay_id=xxxxxx",
	"signType": "RSA",
	"paySign": "签名字符串"
}
```

**前端发起支付：**

```js
function payment() {
    WeixinJSBridge.invoke('getBrandWCPayRequest', $result(后端获取到的返回值),
    function(res) {
        if (res.err_msg == "get_brand_wcpay_request:ok") {
            // 使用以上方式判断前端返回,微信团队郑重提示：
            //res.err_msg将在用户支付成功后返回ok，但并不保证它绝对可靠。
        }
    });
}
if (typeof WeixinJSBridge == "undefined") {
    if (document.addEventListener) {
        document.addEventListener('WeixinJSBridgeReady', onBridgeReady, false);
    } else if (document.attachEvent) {
        document.attachEvent('WeixinJSBridgeReady', onBridgeReady);
        document.attachEvent('onWeixinJSBridgeReady', onBridgeReady);
    }
} else {
    onBridgeReady();
}
```

#### 四、小程序支付：

```php
<?php
require "EasyWeChatPay.php";
$body = [
    "description" => "APIV3网页支付测试",
    "out_trade_no" => date('YmdHis'),
    "notify_url" => "异步通知地址",
    "amount" => [
        "total" => 10,   //金额,单位：元
        'currency' => "CNY"
    ],
    "appid" => "小程序APPID",   //公众号传公众号APPID、小程序传小程序APPID、app传微信开放平台相对应的APPID
    "mchid" => "你的商户号"
];

try {
    $pay = new EasyWeChatPay();
    $pay->setParams($body);
    $pay->setSerialNo("你的V3证书序列号");
    $pay->setKeyPath("证书路径");
    $pay->setType("miniapp");   //支付方式   电脑网页：pc, 公众号: jsapi, 小程序:miniapp, 手机端：h5，app支付： app
    $pay->setOpenId("由小程序获取到的用户openID");  
    $result = $pay->doPayment();
    print_r($result);
}catch (ErrorException $e) {
    echo $e->getMessage();
}
```

**成功返回示例：**

```json
{
	"timeStamp": "xxxxxxx",
    "nonceStr": "xxxxxxxxxxxxxxxxx",
    "package": "prepay_id=wxxxxxxxxx",
    "signType": "RSA",
    "paySign": "签名字符串",
}
```

**小程序发起支付：**

```js
wx.requestPayment
(
	{
		"timeStamp": "xxxxxxxxx",   //依次对顶后端返回的数据
		"nonceStr": "xxxxxxxxxx",
		"package": "prepay_id=xxxxxxxxxxxxx",
		"signType": "RSA",
		"paySign": "xxxxxxxxxxx",
		"success":function(res){},
		"fail":function(res){},
		"complete":function(res){}
	}
)
```

#### 五、**APP支付：**

```php
<?php
require "EasyWeChatPay.php";
$body = [
    "description" => "APIV3网页支付测试",
    "out_trade_no" => date('YmdHis'),
    "notify_url" => "异步通知地址",
    "amount" => [
        "total" => 10,   //金额,单位：元
        'currency' => "CNY"
    ],
    "appid" => "微信开放平台对应APPID",   //公众号传公众号APPID、小程序传小程序APPID、app传微信开放平台相对应的APPID
    "mchid" => "你的商户号"
];

try {
    $pay = new EasyWeChatPay();
    $pay->setParams($body);
    $pay->setSerialNo("你的V3证书序列号");
    $pay->setKeyPath("证书路径");
    $pay->setType("app");   //支付方式   电脑网页：pc, 公众号: jsapi, 小程序:miniapp, 手机端：h5，app支付： app
    $pay->setOpenId("由小程序获取到的用户openID");  
    $result = $pay->doPayment();
    print_r($result);
}catch (ErrorException $e) {
    echo $e->getMessage();
}
```

**成功返回示例：**

```json
{
	"appid": "xxxxxxxx",
    "partnerid":  "xxxxxxxx",
    "timestamp": "xxxxxxxxxp",
    "noncestr": "xxxxxxxxxr",
    "prepayid": "xxxxxxxxxx",
    "package":  "Sign=WXPay",
    "sign": "xxxxxxxxxxx"
}
```

app端获取到数据后调用sdk发起支付即可。

```java
IWXAPI api;
PayReq request = new PayReq();
request.appId = data.appid;               //data为后端返回的数据
request.partnerId = data.partnerid;
request.prepayId= data.prepayid;
request.packageValue = data.package;
request.nonceStr= data.noncestr;
request.timeStamp= data.timestamp;
request.sign= data.sign;
api.sendReq(request);
```

#### 六、异步通知验签

```php
<?php
require "EasyWeChatPay.php";
try {
    $pay = new EasyWeChatPay();
   	$pay->setApiKey("你的APIV3key")
    if($pay->checkSign) { //验签成功
        $responseBody = file_get_contents("php://input");
        $data = (array)json_decode($responseBody, true);
        $decrypeBody = $pay->notifyBodyDecrypt($data["resource"]["ciphertext"],$data["resource"]["nonce"],$data["resource"]["associated_data"]);   //解密后的数据  参考https://pay.weixin.qq.com/wiki/doc/apiv3/apis/chapter3_1_5.shtml
        if($decryptBody["trade_state"] == "SUCCESS") {
            //支付成功  你的业务逻辑
        }
        
    }
}catch (ErrorException $e) {
    echo $e->getMessage();
}
```

