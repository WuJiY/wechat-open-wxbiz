<?php
namespace Wechat\Controller;
use Think\Controller;
class NotifyController extends Controller {



	/**
	 * 获取公众号授权
	 * @return [type] [description]
	 */
    public function authorization(){
    	@file_put_contents(RUNTIME_PATH.'wechat_ticket.xml', @file_get_contents("php://input"));

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
}