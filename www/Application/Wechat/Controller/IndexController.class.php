<?php
namespace Youzan\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('Welcome Youzan sync connector.', 'utf-8');
    }
}