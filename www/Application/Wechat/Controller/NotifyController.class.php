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
        $this->show("<a href='{$redirect_url}'>Wechat Grunt</a>", 'utf-8');
    }

	/**
	 * 获取公众号授权
     * 
     * POST /notify/authorization?signature=a9256d072c4a98e9afb01905e13c349f03091c78&timestamp=1472651585&nonce=1156671907&encrypt_type=aes&msg_signature=f498865b89a15e55dd0c88273f24bda05eae6f3e
     * 
        <xml>
            <AppId><![CDATA[wx6a5c7b3deae109fb]]></AppId>
            <CreateTime>1472650983</CreateTime>
            <InfoType><![CDATA[component_verify_ticket]]></InfoType>
            <ComponentVerifyTicket><![CDATA[ticket@@@sTomyzl5DKMWHThgtqtIrAGsaCSAA5cVNww7rLkIqlABZC00xEDHZnRLiE2-bXsh18toLc6HTZ2rI4uvBJbvHQ]]></ComponentVerifyTicket>
            </xml>

        <xml>
            <AppId><![CDATA[wx6a5c7b3deae109fb]]></AppId>
            <CreateTime>1472651234</CreateTime>
            <InfoType><![CDATA[unauthorized]]></InfoType>
            <AuthorizerAppid><![CDATA[wx0a73c7ae093b4842]]></AuthorizerAppid>
        </xml>
     * 
	 * @return [type] [description]
	 */
    public function authorization(){
        @file_put_contents(RUNTIME_PATH.'wechat_authorization.xml', @file_get_contents("php://input"));

    	if($data = $this->client->checkTicket()){
            @file_put_contents(RUNTIME_PATH."wechat_authorization_decrypt.xml", $this->client->getRevPostXml());

            // TODO: 检查并 开启/关闭 授权状态
            $status = $data['InfoType'] == 'unauthorized' ? 0 : 1;
            D('Wechat')->updateAuthorizeStatus($data['AppId'], $status);
            
            echo 'SUCCESS';
        }else{
            echo 'FAIL';
        }
    }

    /**
     * 授权成功回调地址
     *
     * GET /notify/grant?auth_code=queryauthcode@@@tKwdwJI35Ulk0r00t4MX2VJ-HZ0rjwx-wXtNkMRKe2eSKZquYzcsTPWF1qUeKkZ6bYd2uN0lM0Je_gT20sZ5jA&expires_in=3600
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
     * POST /notify/wx0a73c7ae093b4842/callback?signature=323de029b59fdff88aada25b5c8c2a936287765c&timestamp=1472651721&nonce=1607272680&openid=owdYLj9UVvNI8TIq81rkPA852fdA&encrypt_type=aes&msg_signature=810a4d1ec263ce207b5d9ad0ac61f645a7253712
     * 
         <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472651721</CreateTime>
            <MsgType><![CDATA[event]]></MsgType>
            <Event><![CDATA[subscribe]]></Event>
            <EventKey><![CDATA[]]></EventKey>
        </xml>

        <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472651663</CreateTime>
            <MsgType><![CDATA[event]]></MsgType>
            <Event><![CDATA[unsubscribe]]></Event>
            <EventKey><![CDATA[]]></EventKey>
        </xml>


        <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472651566</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[Hello]]></Content>
            <MsgId>6324990314820393100</MsgId>
        </xml>

        <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472652104</CreateTime>
            <MsgType><![CDATA[event]]></MsgType>
            <Event><![CDATA[LOCATION]]></Event>
            <Latitude>39.980888</Latitude>
            <Longitude>116.300865</Longitude>
            <Precision>65.000000</Precision>
        </xml>

        <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472652641</CreateTime>
            <MsgType><![CDATA[event]]></MsgType>
            <Event><![CDATA[VIEW]]></Event>
            <EventKey><![CDATA[http://m.wecook.cn/?src=caipudaquan]]></EventKey>
            <MenuId>206031589</MenuId>
        </xml>
     * 
     * @param  string $app_id [description]
     * @return [type]         [description]
     */
    public function events($app_id=''){
        @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}.xml", @file_get_contents("php://input"));
        if($this->client->valid()){
            @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_decrypt.xml", $this->client->getRevPostXml());

            $data = $this->client->getRev()->getRevData();
            // TODO:检查并处理该公众号用户操作事件
            //switch($data[''])

            echo 'SUCCESS';
        }else{
            echo 'FAIL';
        }
    }



    public function test(){
        $result = $this->client->getAuthorizerOption('wx0a73c7ae093b4842', 'location_report');
        dump($result);
        //dump($this->client->errCode.','.$this->client->errMsg);
    }
}