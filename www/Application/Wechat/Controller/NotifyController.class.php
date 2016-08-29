<?php
namespace Wechat\Controller;
use Think\Controller;
use Think\Log;
class NotifyController extends Controller {

	/**
	 * 获取公众号授权
	 * @return [type] [description]
	 */
    public function authorization($signature='', $timestamp='', $nonce='', $encrypt_type='', $msg_signature=''){
    	import("@.Org.Wechat.WXBizMsgCrypt");
    	
    	$options = C('WECHAT');
    	$pc = new \WXBizMsgCrypt($options['token'], $options['encodingaeskey'], $options['appid']);

		// 第三方收到公众号平台发送的消息
		$msg = '';
		$xml = file_get_contents("php://input");
		$xml = "<xml><AppId><![CDATA[wx6a5c7b3deae109fb]]></AppId><Encrypt><![CDATA[fF7y1VphrWkPBfLhCEE/IAGLfKEv6GyAdZIu6/7DyMsIPuy0MHUqGDvTbRsVk8vQgzNhDbOIqn0IAw6TXM9HRZcJGFOiuSwmo4bxohMFG/Ob3MgKVM76CWgnk7Gz3Av4FKuc9veB/UsifvHmcnpl6UCqJRn8/BqdotG1lAnzMyuWzqny8f56x/zWjVouC1ILWkAk/iM2M5XeEqjziahbSJ0ABqslBaGYKXogJJ20oVTIzQIPtGPr3uBQ0Kzf8iV4O4tRsH0ZFFSB92sVzEDs1eF0fijLUISKE36AB4QStvC14YtCjMJFMSwjuQ8eR7TRlNebVLbM9jxSHCGql/MreFeZOEHphth39WyHqM9+B41X7+0Xi8vhAHZRDOewIXxtX8hR4y0FUTGVdCfCy8v5UH4HXlEaoOjxfMxSzMqMeSxTWl7pvnnQpkiIyikekUokiEu+69mopvN522HhmwwOTQ==]]></Encrypt></xml>";
		$errCode = $pc->decryptMsg($msg_signature, $timestamp, $nonce, $xml, $msg);

		$log = "[WECHAT-NOTIFY-Authorization]: signature:{$signature}\ntimestamp:{$signature}\nnonce:{$nonce}\nencrypt_type:{$encrypt_type}\nmsg_signature:{$msg_signature}\nXML: {$xml}\nRESULT:{$errCode}\nMSG:{$msg}";
		@file_put_contents(RUNTIME_PATH.'wechat_authorization.xml', $log);
		Log::write('WECHAT: '.$log, Log::DEBUG);

		if($errCode!=0){
			echo 'FAIL';
			return;
		}
		
		
    	
    	echo 'SUCCESS';
    }

    /**
     * 获取公众号事件
     * @param  string $app_id [description]
     * @return [type]         [description]
     */
    public function events($app_id=''){
    	@file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}.xml", @file_get_contents("php://input"));

    	echo 'SUCCESS';
    }


    /**
	 * 获取公众号授权
	 * @return [type] [description]
	 */
    public function ticket(){
    	@file_put_contents(RUNTIME_PATH.'wechat_ticket.xml', @file_get_contents("php://input"));

    	echo 'SUCCESS';
    }
}