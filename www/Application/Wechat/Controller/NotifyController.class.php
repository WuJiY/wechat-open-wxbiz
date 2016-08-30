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

	/**
	 * 获取公众号授权
	 * @return [type] [description]
	 */
    public function authorization(){
    	if($valid = $this->client->valid()){
            $data = $this->client->getRev()->getRevData();
            S('WECHAT_COMPONENT_TICKET', $data['ComponentVerifyTicket']);

            @file_put_contents(RUNTIME_PATH.'wechat_authorization.xml', $this->client->getRevPostXml());

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