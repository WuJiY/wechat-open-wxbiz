<?php
namespace Wechat\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
    	$this->show("Welcome Open Weixin connector.", 'utf-8');
    }


    public function test(){
    	import("@.Org.Wechat.TPWechat");
    	$wechat = new TPWechat(array(
    		'token'             => 'mwecookcn',
	        'appid'             => 'wx6a5c7b3deae109fb',
	        //'appsecret'         => '5ee42c4df454aa74f652a2b62a13fe96',
	        'encodingaeskey'    => 'XKymxSuMODUKy61arYTdD3BfuZ1SnzSDcXlivVGrPm9',
    	));

    	$refesh = 'refreshtoken@@@agUSmdSjVmu1_AauI6lWOjYkS-mRYULpI7UfXsIJg8s';
    }
}