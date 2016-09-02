<?php
namespace Wechat\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
    	$this->show("Welcome Open Weixin connector.", 'utf-8');
    }


    public function test(){
    	import("@.Org.Wechat.TPWechat");

        import("@.Org.Wechat.TPWXBiz");
    	$wechat = new \TPWechat(array(
    		'token'             => 'mwecookcn',
	        'appid'             => 'wx6a5c7b3deae109fb',
	        //'appsecret'         => '5ee42c4df454aa74f652a2b62a13fe96',
	        'encodingaeskey'    => 'XKymxSuMODUKy61arYTdD3BfuZ1SnzSDcXlivVGrPm9',
    	));

    	$access_token  = 'bjztZGHGkrYufA-UwoJ1F8DQLfazI1ainBNw3uVxKUf70oVrmHcGtbnEBVOn90oBnZint8YSC1ev4_SHm-o8ufe3Enog4EKYO-li6VPrn-L0KEQoER_B5fmlmD7VKWnyXXUfAFDOOL';
        $wechat->checkAuth('', '', $access_token, 3600);
        
        $data = $wechat->getUserList();
        dump($data);
    }
}