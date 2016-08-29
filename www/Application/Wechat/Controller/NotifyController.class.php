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
		$errCode = $pc->decryptMsg($msg_signature, $timestamp, $nonce, $xml, $msg);

		$log = "[WECHAT-NOTIFY-Authorization]: signature:{$signature}\ntimestamp:{$signature}\nnonce:{$nonce}\nencrypt_type:{$encrypt_type}\nmsg_signature:{$msg_signature}\nXML: {$xml}\nRESULT:{$errCode}\nMSG:{$msg}";
		@file_put_contents(RUNTIME_PATH.'wechat_authorization.xml', $log);
		Log::write('WECHAT: '.$log, Log::DEBUG);

		if($errCode==0){
			echo 'SUCCESS';
		}else{
			echo 'FAIL';
		}
    	
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