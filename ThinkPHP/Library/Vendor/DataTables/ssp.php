<?php
// +----------------------------------------------------------------------
// | Wecook CMS [ 会做菜, 更懂爱 ]
// +----------------------------------------------------------------------
// | Copyright (c) 2013 http://www.wecook.cn All rights reserved.
// +----------------------------------------------------------------------
// | Author: yhostc <yhostc@gmail.com>
// +----------------------------------------------------------------------

/**
 * DataTable 控制器
 * 主要用于该插件的数据组织
 */
class SSP{
	
	/**
	 * Create the data output array for the DataTables rows
	 *
	 * @param array $columns
	 *        	Column information array
	 * @param array $data
	 *        	Data from the SQL get
	 * @return array Formatted data in a row based format
	 */
	static function data_output($columns, $data) {
		$out = array ();
		for($i = 0, $ien = count ( $data ); $i < $ien; $i ++) {
			$row = array ();
			
			for($j = 0, $jen = count ( $columns ); $j < $jen; $j ++) {
				$column = $columns [$j];
				
				// Is there a formatter?
				if (isset ( $column ['formatter'] )) {
					$row [$column ['dt']] = $column ['formatter'] ( $data [$i] [$column ['db']], $data [$i] );
				} else {
					$row [$column ['dt']] = $data [$i] [$columns [$j] ['db']];
				}
			}
			
			$out [] = $row;
		}
		return $out;
	}
	
	/**
	 * Paging
	 *
	 * Construct the LIMIT clause for server-side processing SQL query
	 *
	 * @param array $request
	 *        	Data sent to server by DataTables
	 * @param array $columns
	 *        	Column information array
	 * @return string SQL limit clause
	 */
	static function limit($request, $columns) {
		$limit = '';
		
		if (isset ( $request ['start'] ) && $request ['length'] != - 1) {
			$limit = intval ( $request ['start'] ) . ", " . intval ( $request ['length'] );
		}
		return $limit;
	}
	
	/**
	 * Ordering
	 *
	 * Construct the ORDER BY clause for server-side processing SQL query
	 *
	 * @param array $request
	 *        	Data sent to server by DataTables
	 * @param array $columns
	 *        	Column information array
	 * @return string SQL order by clause
	 */
	static function order($request, $columns) {
		$order = '';
		
		if (isset ( $request ['order'] ) && count ( $request ['order'] )) {
			$orderBy = array ();
			$dtColumns = self::pluck ( $columns, 'dt' );
			
			for($i = 0, $ien = count ( $request ['order'] ); $i < $ien; $i ++) {
				// Convert the column index into the column data property
				$columnIdx = intval ( $request ['order'] [$i] ['column'] );
				$requestColumn = $request ['columns'] [$columnIdx];
				
				$columnIdx = array_search ( $requestColumn ['data'], $dtColumns );
				$column = $columns [$columnIdx];
				
				if ($requestColumn ['orderable'] == 'true') {
					$dir = $request ['order'] [$i] ['dir'] === 'asc' ? 'ASC' : 'DESC';
					
					$orderBy [] = '`' . $column ['db'] . '` ' . $dir;
				}
			}
			
			//$order = 'ORDER BY ' . implode ( ', ', $orderBy );
			$order = implode ( ', ', $orderBy );
		}
		
		return $order;
	}
	
	/**
	 * Searching / Filtering
	 *
	 * Construct the WHERE clause for server-side processing SQL query.
	 *
	 * NOTE this does not match the built-in DataTables filtering which does it
	 * word by word on any field. It's possible to do here performance on large
	 * databases would be very poor
	 *
	 * @param array $request
	 *        	Data sent to server by DataTables
	 * @param array $columns
	 *        	Column information array
	 * @param array $bindings
	 *        	Array of values for PDO bindings, used in the
	 *        	sql_exec() function
	 * @return string SQL where clause
	 */
	static function filter($request, $columns, &$bindings) {
		$globalSearch = array ();
		$columnSearch = array ();
		$dtColumns = self::pluck ( $columns, 'dt' );
		
		// 全局模糊搜索
		if (isset ( $request ['search'] ) && $request ['search'] ['value'] != '') {
			$str = $request ['search'] ['value'];
			
			for($i = 0, $ien = count ( $request ['columns'] ); $i < $ien; $i ++) {
				$requestColumn = $request['columns'][$i];
				$columnIdx = array_search($requestColumn['data'], $dtColumns);
				$column = $columns [$columnIdx];
				
				if ($requestColumn ['searchable'] == 'true') {
					$globalSearch [] = "`" . $column ['db'] . "` LIKE '%$str%'" ;
				}
			}
		}
		
		
		// 独立字段过滤条件
		for($i = 0, $ien = count ( $request ['columns'] ); $i < $ien; $i ++) {
			$requestColumn = $request['columns'][$i];
			$columnIdx = array_search($requestColumn['data'], $dtColumns );
			$column = $columns[$columnIdx];
			
			$str = $requestColumn['search']['value'];
			if ($requestColumn['searchable'] == 'true' && $str != '') {
				$expression = $column['expression'] ? $column['expression'] : 'LIKE';
				if(isset($column['expression'])){
					$columnSearch [] = $column['expression']($str);
				}else{
					// 检查是否有反格式化
					if (isset($column['reformatter'])) {
						$columnSearch [] = "`" .$column['db']. "`='".$column['reformatter']($str)."'";
					} else {
						$columnSearch [] = "`" .$column['db']. "` LIKE '%$str%'";
					}
				}
			}
		}
		
		// Combine the filters into a single string
		$where = '';
		
		if (count ( $globalSearch )) {
			$where = implode ( ' OR ', $globalSearch );
		}
		
		if (count ( $columnSearch )) {
			$where = $where === '' ? implode ( ' AND ', $columnSearch ) : $where . ' AND ' . implode ( ' AND ', $columnSearch );
		}
		
		return $where;
	}
	
	/**
	 * Perform the SQL queries needed for an server-side processing requested,
	 * utilising the helper functions of this class, limit(), order() and
	 * filter() among others.
	 * The returned array is ready to be encoded as JSON
	 * in response to an SSP request, or can be modified if needed before
	 * sending back to the client.
	 *
	 * @param array $request
	 *        	Data sent to server by DataTables
	 * @param array $sql_details
	 *        	SQL connection details - see sql_connect()
	 * @param string $table
	 *        	SQL table to query
	 * @param string $primaryKey
	 *        	Primary key of the table
	 * @param array $columns
	 *        	Column information array
	 * @return array Server-side processing response array
	 */
	static function simple($model, $columns, $request, $relation=false, $sub) {
		$bindings = array();
		$diffColumns = array();
		foreach ($columns as $row){
			if(in_array($row['db'], $model->getDbFields())){
				$diffColumns[] = $row;
			}
		}
		
		// Build the SQL query string from the request
		$limit = self::limit ( $request, $diffColumns );
		$order = self::order ( $request, $diffColumns );
		$where = self::filter ( $request, $diffColumns, $bindings );
		
 		// Main query to actually get the data
		if($relation){
			$model->relation(true);
		}
		
		// 是否进行子查询
 		if ($sub) {
 			$data = $model->table($sub.' a')->field("SQL_CALC_FOUND_ROWS *")->where($where)->order($order)->limit($limit)->select();
 			$recordsFiltered = $model->table($sub.' a')->where($where)->count();
 			$recordsTotal = $model->table($sub.' a')->count();
 		}else{
 			$data = $model->field("SQL_CALC_FOUND_ROWS *")->where($where)->order($order)->limit($limit)->select();
 			$recordsFiltered = $model->where($where)->count();
 			$recordsTotal = $model->count();
 		}
 		
		/*
		 * Output
		 */
		return array (
			"draw" => intval ( $request ['draw'] ),
			"recordsTotal" => intval ( $recordsTotal ),
			"recordsFiltered" => intval ( $recordsFiltered ),
			"data" => self::data_output ($columns, $data ? $data : array() ) 
		);
	}
	
	
	/*
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * Internal methods
	 */
	
	/**
	 * Throw a fatal error.
	 *
	 * This writes out an error message in a JSON string which DataTables will
	 * see and show to the user in the browser.
	 *
	 * @param string $msg
	 *        	Message to send to the client
	 */
	static function fatal($msg) {
		echo json_encode ( array (
			"error" => $msg 
		));
		
		exit ( 0 );
	}
	
	/**
	 * Create a PDO binding key which can be used for escaping variables safely
	 * when executing a query with sql_exec()
	 *
	 * @param
	 *        	array &$a Array of bindings
	 * @param * $val
	 *        	Value to bind
	 * @param int $type
	 *        	PDO field type
	 * @return string Bound key to be used in the SQL where this parameter
	 *         would be used.
	 */
	static function bind(&$a, $val, $type) {
		$key = ':binding_' . count ( $a );
		
		$a [] = array (
			'key' => $key,
			'val' => $val,
			'type' => $type 
		);
		
		return $key;
	}
	
	/**
	 * Pull a particular property from each assoc.
	 * array in a numeric array,
	 * returning and array of the property values from each item.
	 *
	 * @param array $a
	 *        	Array to get data from
	 * @param string $prop
	 *        	Property to read
	 * @return array Array of property values
	 */
	static function pluck($a, $prop) {
		$out = array ();
		
		for($i = 0, $len = count ( $a ); $i < $len; $i ++) {
			$out [] = $a [$i] [$prop];
		}
		
		return $out;
	}
}
?>