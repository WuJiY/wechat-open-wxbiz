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

    	if($data = $this->client->checkTicket()){
            @file_put_contents(RUNTIME_PATH."wechat_authorization_decrypt.xml", $this->client->getRevPostXml());
            echo 'SUCCESS';
        }else{
            echo 'FAIL';
        }
    }

    /**
     * 授权成功回调地址
     */
    public function grant($auth_code='', $expires_in='3600'){
        // 获取授权信息
        if($authorization_info = $this->client->getAuthorization($auth_code, $expires_in)){
            $data = array(
                'appid'             => $authorization_info['authorizer_appid'],
                'refresh_token'     => $authorization_info['authorizer_refresh_token'],
            );
            
            // 获取公众号基本信息
            $model = D('Wechat');
            if($authorizer_id = $model->where(array('appid'=>$authorization_info['authorizer_appid']))->getField('id')){
                // 更新授权
                $data['id'] = $authorizer_id;
            }

            if($info = $this->client->getAuthorizerInfo($authorization_info['authorizer_appid'])){
                $authorizer_info = $info['authorizer_info'];
                $data = array_merge($data, array(
                    'nick_name'     => (string)$authorizer_info['nick_name'],
                    'head_img'      => (string)$authorizer_info['head_img'],
                    'service_type'  => (string)$authorizer_info['service_type_info']['id'],
                    'verify_type'   => (string)$authorizer_info['verify_type_info']['id'],
                    'user_name'     => (string)$authorizer_info['user_name'],
                    'alias'         => (string)$authorizer_info['alias'],
                    'qrcode_url'    => (string)$authorizer_info['qrcode_url'],
                    'func_info'     => (string)implode(",", $this->getFuncInfo($info['authorization_info']['func_info'])),
                    'business_info' => @json_encode($authorizer_info['business_info'])
                ));
            }

            if($model->update($data)){
                echo 'GRANT SUCCESS!';
            }else{
                echo 'GRANT FAIL';
                dump($model->getLastSql());
            }
        }else{
            echo 'GRANT FAIL, ERROR:'.$this->client->errCode.','.$this->client->errMsg;
        }
    }

    private function getFuncInfo($func_info=array()){
        $ids = [];
        foreach ($func_info as $row) {
            $ids[] = $row['funcscope_category']['id'];
        }
        sort($ids);
        return $ids;
    }

    /**
     * 公众号授权事件
     *
     * array(6) {
          ["ToUserName"] => string(15) "gh_7d2bd24b4d3b"
          ["FromUserName"] => string(28) "owdYLj4vfuMMCcc8ogFqLUFsMCYw"
          ["CreateTime"] => string(10) "1472647478"
          ["MsgType"] => string(5) "event"
          ["Event"] => string(11) "unsubscribe"
          ["EventKey"] => object(SimpleXMLElement)#8 (0) {
          }
        }
     * 
     * @param  string $app_id [description]
     * @return [type]         [description]
     */
    public function events($app_id=''){
        @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}.xml", @file_get_contents("php://input"));
        if($this->client->valid()){
            @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}.xml", $this->client->getRevPostXml());

            $data = $this->client->getRev()->getRevData();

            //switch($data[''])

            echo 'SUCCESS';
        }else{
            echo 'FAIL';
        }
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
        $result = $this->client->getAuthorizerOption('wx0a73c7ae093b4842', 'location_report');
        dump($result);
        //dump($this->client->errCode.','.$this->client->errMsg);
    }
}