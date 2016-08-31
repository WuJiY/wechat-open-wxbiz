<?php
// +----------------------------------------------------------------------
// | Wecook Api Service
// +----------------------------------------------------------------------
// | Copyright (c) 2016 http://www.wecook.cn All rights reserved.
// +----------------------------------------------------------------------
// | Author: TIGERB <zhan.shi@wecook.cn>
// +----------------------------------------------------------------------

namespace Wechat\Model;
use Think\Model;

class WechatModel extends Model
{
    /**
     * 表名
     * @var string
     */
    protected $trueTableName = 'mk_wechat';

    /* 用户模型自动完成 */
    protected $_auto = array(
        array('create_time', NOW_TIME, self::MODEL_INSERT),
        array('update_time', NOW_TIME, self::MODEL_BOTH),
        array('status', '1', self::MODEL_INSERT)
    );
    
    /**
     * 新增或更新一个文档
     * 
     * @param array $data   手动传入的数据
     * @return boolean fasle 失败 ， int 成功 返回完整的数据
     * @author yhostc <yhostc@gmail.com>
     */
    public function update($data = null){
        /* 获取数据对象 */
        $data = $this->create($data);
        if(empty($data)){
            return false;
        }
        
        /* 添加或新增基础内容 */
        if(empty($data['id'])){ //新增数据
            $id = $this->add(); //添加基础内容
            if(!$id){
                $this->error = '新增出错！';
                return false;
            }
            $data['id'] = $id;
        } else { //更新数据
            $status = $this->save(); //更新基础内容
            if(false === $status){
                $this->error = '更新出错！';
                return false;
            }
        }
        
        //内容添加或更新完成
        return $data;
    }
}
