<?php

namespace Org;
class ElasticSearch {
	
	
	private $host = "";
	private $auth = "";
	private $index = "";
	private $type = "";
	
	private $from = 0;
	private $size = 10;
	private $dsn = "";
	
	
	/**
	 * 构造函数
	 */
	public function __construct($config) {
		$this->host = $config['host'];
		$this->auth = $config['auth'];
		$this->index = $config['index'];
		$this->type = $config['type'];
		
	}
	
	
	public function where(){
		return $this;
	}
	
	/**
	 * limit for query
	 * @param number $limit
	 * @return \Org\ElasticSearch
	 */
	public function limit($limit=10){
		$p = explode(",", $limit);
		if(count($p)>1){
			$this->_from = $p[0];
			$this->_size = $p[1];
		}else{
			$this->_size = $limit;
		}
		return $this;
	}
	
	/**
	 * fields
	 * @param unknown $fields
	 * @return \Org\ElasticSearch
	 */
	public function field($fields){
		$this->_field = $fields;
		return $this;
	}
	
	/**
	 * Order
	 * @param array|string $order
	 * @return \Org\ElasticSearch
	 */
	public function order($order){
		if(is_array($order)){
			
		}else if(is_string($order)){
			$o 		= explode(",", $order);
			$order 	= array();
			for($i=0; $i<count($o); $i++){
				$itm = explode(" ", $o[$i]);
				$order[] = array($itm[0], array("order"=>$itm[1]));
			}
		}else{
			throw "UnSupport Order Type!";
		}
		
		$this->_order = array_merge(array("_score"), $order);
		return $this;
	}
	
	public function select(){
		$query = array(
			
		);
		
		
		dump($this->_where);
		dump($this->_limit);
		dump($this->_sort);
	}
	
	
	
	/**
	 * 条件查询
	 * @param array $query
	 * @return JSON
	 */
	public function query($query){
		$dsn = $this->getDSN('_search');
		return $this->curl_query($dsn, $query);
	}

	/**
	 * 创建索引
	 * @param array $query
	 * @return JSON
	 */
	public function create($id, $data){
		if (empty($id)) {
			return '请传入id';
		}
		$dsn = $this->getDSN($id);
		return $this->curl_query($dsn, $data);
	}

	/**
	 * 删除索引
	 * @param array $query
	 * @return JSON
	 */
	public function delete($id){
		if (empty($id)) {
			return '请传入id';
		}
		$dsn = $this->getDSN($id);
		return $this->http_delete($dsn);
	}

	/**
	 * 输入提示
	 * @param string $keywords
	 * @return JSON
	 */
	public function suggest($keywords){
		$dsn = $this->getDSN('_suggest');
		$query = array(
			"suggestion"	=> array(
				"text" 			=> $keywords,
				"completion" 	=> array("field" => "suggest")
			)
		);
		
		return $this->curl_query($dsn, $query);
	}
	
	/**
	 * 发送请求进行查询
	 * @param 搜索DSN $dsn
	 * @param 查询条件 $query
	 * @return JSON
	 */
	protected function curl_query($dsn, $query){
		$curl = curl_init();
 		curl_setopt($curl, CURLOPT_URL, $dsn);
 		curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_TIMEOUT_MS, 1000);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);
		curl_setopt($curl, CURLOPT_HEADER, false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($curl, CURLOPT_TCP_NODELAY, false);
		if($this->auth){
			curl_setopt($curl, CURLOPT_USERPWD, $this->auth);
		}
		curl_setopt($curl, CURLOPT_USERAGENT, "wecook service api/2.0");
		curl_setopt($curl, CURLOPT_POSTFIELDS, @json_encode($query, JSON_UNESCAPED_UNICODE));
		
		$result = curl_exec($curl);
		$error = curl_error($curl);
		
		return json_decode($result, true);
	}

	/**
	* DELETE 请求
	* @param string $url
	*/
	private function http_delete($url){
		$oCurl = curl_init();
		if(stripos($url,"https://")!==FALSE){
			curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
			curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, FALSE);
			curl_setopt($oCurl, CURLOPT_SSLVERSION, 1); //CURL_SSLVERSION_TLSv1
		}
		curl_setopt($oCurl, CURLOPT_URL, $url);
		curl_setopt($oCurl, CURLOPT_CUSTOMREQUEST, 'DELETE');
		curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt($oCurl, CURLOPT_TIMEOUT, 10);
		$sContent = curl_exec($oCurl);
		$aStatus = curl_getinfo($oCurl);
		curl_close($oCurl);
		if(intval($aStatus["http_code"])==200){
			return json_decode($sContent, true);
		}else{
			return false;
		}
	}
	
	protected function getDSN($type='_search'){
		$dsn = $this->host. "/". $this->index;
		if($this->type){
			$dsn .= "/".$this->type;
		}
		$dsn .= "/".$type;
		return $dsn;
	}
	
	
	
	/**
	 * 析构函数
	 */
	function __destruct() {
		
	}
}


/**
 * DEMO1: QUERY
 * 
	$search = new \Org\ElasticSearch(array(
		"host"	=> 'http://s.wecook.com.cn',
		"index"	=> 'wecook'
	));
	$list = $search->query(array(
		"query"	=>	array(
			'term'	=> array(
				'title'=>$keywords
			)
		)
	));
 */


?>
