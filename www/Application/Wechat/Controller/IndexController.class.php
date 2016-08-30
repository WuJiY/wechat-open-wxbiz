<?php
namespace Wechat\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
    	$this->show("Welcome Open Weixin connector.", 'utf-8');
    }
}