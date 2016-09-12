<?php
namespace Wechat\Controller;
use Think\Controller;
class NotifyController extends Controller {

    private $client;
    private $test_app_id = 'gh_3c884a361561';   // 全网发布测试公众号

    /**
     * 引入SDK
     * @return 
     */
    public function _initialize(){
        import("@.Org.Wechat.TPWXBiz");
        $this->client = new \TPWXBiz(C('WECHAT_WXBIZ')); //创建实例对象
    }

    public function index(){
        $redirect_url = $this->client->getGrantUrl('http://'.$_SERVER["SERVER_NAME"].U('Notify/grant'));
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
     */
    public function authorization(){
        @file_put_contents(RUNTIME_PATH.'wechat_authorization.xml', @file_get_contents("php://input"));

        if($data = $this->client->checkTicket()){
            @file_put_contents(RUNTIME_PATH."wechat_authorization_decrypt.xml", $this->client->getRevPostXml());

            if($data['InfoType'] == 'unauthorized'){
                D('Wechat')->updateAuthorizeStatus($data['AuthorizerAppid'], 0);
            }
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
        @file_put_contents(RUNTIME_PATH.'wechat_grant.xml', @file_get_contents("php://input"));

        // 获取授权信息
        if($authorization_info = $this->client->getAuthorization($auth_code, $expires_in)){
            @file_put_contents(RUNTIME_PATH.'wechat_grant_decrypt.xml', @json_encode(authorization_info, JSON_UNESCAPED_UNICODE));

            $data = array(
                'appid'             => $authorization_info['authorizer_appid'],
                'refresh_token'     => $authorization_info['authorizer_refresh_token'],
                'status'            => 1
            );
            
            // 获取公众号基本信息
            $model = D('Wechat');
            if($authorizer_id = $model->where(array('appid'=>$authorization_info['authorizer_appid']))->getField('id')){
                // 更新授权
                $data['id'] = $authorizer_id;
            }

            if($info = $this->client->getAuthorizerInfo($authorization_info['authorizer_appid'])){
                $authorizer_info = $info['authorizer_info'];
                $data = @array_merge($data, array(
                    'nick_name'     => (string)$authorizer_info['nick_name'],
                    'head_img'      => (string)$authorizer_info['head_img'],
                    'service_type'  => (string)$authorizer_info['service_type_info']['id'],
                    'verify_type'   => (string)$authorizer_info['verify_type_info']['id'],
                    'user_name'     => (string)$authorizer_info['user_name'],
                    'alias'         => (string)$authorizer_info['alias'],
                    'qrcode_url'    => (string)$authorizer_info['qrcode_url'],
                    'func_info'     => (string)implode(",", $this->getFuncInfo($info['authorization_info']['func_info'])),
                    'business_info' => @json_encode($authorizer_info['business_info'], JSON_UNESCAPED_UNICODE)
                ));
            }

            if($model->update($data)){
                echo 'GRANT SUCCESS!';
            }else{
                echo 'GRANT FAIL';
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
            <ToUserName><![CDATA[gh_3c884a361561]]></ToUserName>
            <FromUserName><![CDATA[ozy4qt0Rsc9YJzR5nEeVAaTHg9DQ]]></FromUserName>
            <CreateTime>1472818491</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[QUERY_AUTH_CODE:queryauthcode@@@mLsxqNd9yYHkak0invO_ZTDZ_JnKIDC7LNE0-xR6My7isl15uc_v7E6QWH1f0HIABhwA7AwEduKt-2CayEIvcw]]></Content>
            <MsgId>6325707252193792008</MsgId>
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

        <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472790655</CreateTime>
            <MsgType><![CDATA[event]]></MsgType>
            <Event><![CDATA[subscribe]]></Event>
            <EventKey><![CDATA[qrscene_1]]></EventKey>
            <Ticket><![CDATA[gQGY8DoAAAAAAAAAASxodHRwOi8vd2VpeGluLnFxLmNvbS9xL3RYU2J3eDNsSzR4U2JVakdabGdGAAIEiS62VAMEAAAAAA==]]></Ticket>
        </xml>

        <xml>
            <ToUserName><![CDATA[gh_7d2bd24b4d3b]]></ToUserName>
            <FromUserName><![CDATA[owdYLj9UVvNI8TIq81rkPA852fdA]]></FromUserName>
            <CreateTime>1472790609</CreateTime>
            <MsgType><![CDATA[event]]></MsgType>
            <Event><![CDATA[SCAN]]></Event>
            <EventKey><![CDATA[1]]></EventKey>
            <Ticket><![CDATA[gQGY8DoAAAAAAAAAASxodHRwOi8vd2VpeGluLnFxLmNvbS9xL3RYU2J3eDNsSzR4U2JVakdabGdGAAIEiS62VAMEAAAAAA==]]></Ticket>
        </xml>

     * 
     * @param  string $app_id [description]
     * @return [type]         [description]
     */
    public function events($app_id=''){
        $time = date('YmdHis', time());
        // @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_{$time}.xml", @file_get_contents("php://input"));
        // @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_{$time}_url.xml", $_SERVER["REQUEST_URI"]);
        if($this->client->valid()){
            @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_{$time}_decrypt.xml", $this->client->getRevPostXml());
            $data = $this->client->getRev()->getRevData();
            
            // 检查并记录二维码扫码信息
            // if($data['ToUserName']=='gh_7d2bd24b4d3b' && $data['EventKey'] && ($data['Event']=='subscribe' || $data['Event']=='SCAN')){
            //     $sence_id = @str_ireplace('qrscene_', '', $data['EventKey']);
            // }

            // For publish testing
            if($data['ToUserName'] == $this->test_app_id){
                $msg = $this->publishTesting($data);
            }
            
            if(isset($msg)){
                $this->client->text((string)$msg)->reply();
            }
        }else{
            echo 'FAIL';
        }
    }

    /**
     * 全网发布自动化测试
     * @param  array $data  推送数据
     * @return string 
     */
    private function publishTesting($data){
        // Event testing
        if($data['MsgType']=='event'){
            $msg = $data['Event'].'from_callback';
        }

        // Text testing
        if($data['MsgType']=='text'){
            if(preg_match("/TESTCOMPONENT_MSG_TYPE_TEXT/", $data['Content'])){
                $msg = 'TESTCOMPONENT_MSG_TYPE_TEXT_callback';
            }

            if(preg_match("/QUERY_AUTH_CODE/", $data['Content'])){
                $query_auth_code = @trim(@str_replace("QUERY_AUTH_CODE:", "", $data['Content']));

                // @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_{$time}_auth1.xml", $query_auth_code);
                try{
                    $auth = $this->client->getAuthorization($query_auth_code);
                }catch(Exception $e){
                    // @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_{$time}_ERR.xml", $e->getMessage());
                }
                // @file_put_contents(RUNTIME_PATH."wechat_events_{$app_id}_{$time}_auth2.xml", json_encode($auth, JSON_UNESCAPED_UNICODE));

                import("@.Org.Wechat.TPWechat");
                $wechat = new \TPWechat();
                $wechat->checkAuth('', '', $auth['authorizer_access_token'], 3600);
                $wechat->sendCustomMessage(array(
                    'touser'    => $data['FromUserName'],
                    'msgtype'   => 'text',
                    'text'      => array('content'=>"{$query_auth_code}_from_api")
                ));
                $msg = '';
            }
        }

        return $msg;  
    }

    /**
     * 获取授权公众号参数信息
     */
    public function getAuthorizerOption($wechat_id='10002'){
        $wechat = D('Wechat')->getInfo($wechat_id);
        $result = $this->client->getAuthorizerOption($wechat['appid'], 'location_report');
        dump($result);
        //dump($this->client->errCode.','.$this->client->errMsg);
    }

    /**
     * 获取授权公众号接口access token
     */
    public function getAuthorizerAccessToken($wechat_id='10002'){
        $wechat = D('Wechat')->getInfo($wechat_id);
        $access_token = $this->client->getAuthorizerAccessToken($wechat['appid'], $wechat['refresh_token']);
        dump($access_token);
        //dump($this->client->errCode.','.$this->client->errMsg);
    }

    /**
     * 调用公众号接口示例
     * @return [type] [description]
     */
    public function getUserList($wechat_id='10002'){
        $wechat = D('Wechat')->getInfo($wechat_id);
        dump($wechat);
        $access_token = $this->client->getAuthorizerAccessToken($wechat['appid'], $wechat['refresh_token']);
        dump($access_token);

        import("@.Org.Wechat.TPWechat");
        $client = new \TPWechat(array(
            'token'             => 'mwecookcn',
            'appid'             => $wechat['appid'],
            //'appsecret'       => '5ee42c4df454aa74f652a2b62a13fe96',
            'encodingaeskey'    => 'XKymxSuMODUKy61arYTdD3BfuZ1SnzSDcXlivVGrPm9',
        ));

        $client->checkAuth('', '', $access_token, 3600);
        
        $data = $client->getUserList();
        dump($data);
    } 

    /**
     * 调用公众号接口示例
     * @return [type] [description]
     */
    public function getUserInfo($wechat_id='10002', $openid='owdYLjyJJcEvSPFiIGnYh1xAfCOo'){
        $wechat = D('Wechat')->getInfo($wechat_id);
        $access_token = $this->client->getAuthorizerAccessToken($wechat['appid'], $wechat['refresh_token']);
        
        import("@.Org.Wechat.TPWechat");
        $client = new \TPWechat(array(
            'token'             => 'mwecookcn',
            'appid'             => $wechat['appid'],
            //'appsecret'       => '5ee42c4df454aa74f652a2b62a13fe96',
            'encodingaeskey'    => 'XKymxSuMODUKy61arYTdD3BfuZ1SnzSDcXlivVGrPm9',
        ));

        $client->checkAuth('', '', $access_token, 3600);
        
        $data = $client->getUserInfo($openid);
        dump($data);
    } 
}