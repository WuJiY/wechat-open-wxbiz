<?php
namespace Wechat\Controller;
use Think\Controller;
class NotifyController extends Controller {

    private $client;

    /**
     * 引入SDK
     * @return 
     */
    public function _initialize(){
        import("@.Org.Wechat.TPWXBiz");
        $this->client = new \TPWXBiz(C('WECHAT')); //创建实例对象
    }

    public function index(){
        $redirect_url = $this->client->getGrantUrl("http://wx.wecook.cn/notify/grant");
        $this->show("<a href='{$redirect_url}'>GRANT</a>", 'utf-8');
    }

	/**
	 * 1、推送，获取公众号授权
	 * @return [type] [description]
	 */
    public function authorization(){
        @file_put_contents(RUNTIME_PATH.'wechat_authorization.xml', @file_get_contents("php://input"));

    	if($decrypt = $this->client->updateTicket()){
            echo 'SUCCESS';
        }else{
            echo 'FAIL';
        }
    }

    /**
     * 授权成功回调地址
     */
    public function grant($auth_code='', $expires_in='3600'){
        dump($auth_code);

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


    public function test(){

        $token = $this->client->getPreAuthCode();
        dump($token);
    }
}