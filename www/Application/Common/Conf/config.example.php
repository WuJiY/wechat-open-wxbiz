<?php
return array(
     /* URL配置 */
    'URL_CASE_INSENSITIVE' => true,    //默认false 表示URL区分大小写 true则表示不区分大小写
    'URL_MODEL'            => 2,       //URL模式

    'DEFAULT_MODULE' 		=> 'Wechat',
    'MODULE_ALLOW_LIST' 	=> array('Wechat'),
    'MODULE_DENY_LIST' 		=> array('Common'),

    'URL_ROUTER_ON'		=> true, 
    'URL_ROUTE_RULES'       	=> array(
        'notify/:app_id/callback' => array('Notify/events'),
    ),

    'LOG_RECORD'            => true,   			// 默认不记录日志
    'LOG_TYPE'              => 'File', 			// 日志记录类型 默认为文件方式
    'LOG_LEVEL'             => 'EMERG,ALERT,CRIT,ERR,SQL,DEBUG',	// 允许记录的日志级别
    'LOG_EXCEPTION_RECORD'  => true,    		// 是否记录异常信息日志

    /* 数据库配置 */
    'DB_TYPE'               => 'mysql',         // 数据库类型
    'DB_HOST'               => '',              // 服务器地址
    'DB_NAME'               => '',              // 数据库名
    'DB_USER'               => '',              // 用户名
    'DB_PWD'                => '',              // 密码
    'DB_PORT'               => '',              // 端口
    'DB_PREFIX'             => '',              // 数据库表前缀

    /* 公众号配置 */
    'WECHAT_WXBIZ'          => array(
        /* 开放平台设置 */
        'token'             => '',
        'appid'             => '',
        'appsecret'         => '',
        'encodingaeskey'    => '',
    ),


    /* 系统缓存 */
    'DATA_CACHE_TYPE'       => 'Redis',
    'REDIS_HOST'            => '',
    'REDIS_PORT'            => '',
    'DATA_CACHE_TIME'       => '',
);

