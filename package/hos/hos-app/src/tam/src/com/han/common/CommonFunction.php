<?php 
class CommonFunction{
	/***
	*  crul工具,未使用curl_multi_exec
	***/
	function callInterfaceCommon($URL,$type,$params,$headers){
		$ch = curl_init();
		$timeout = 5;
		curl_setopt ($ch, CURLOPT_URL, $URL);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:','Content-type: text/json'));
		curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_NOSIGNAL, true);    //注意，毫秒超时一定要设置这个  
		curl_setopt($ch, CURLOPT_TIMEOUT_MS, 3000); //超时时间2000毫秒  
		switch ($type){
			case "GET" : curl_setopt($ch, CURLOPT_HTTPGET, true);break;
			case "POST": curl_setopt($ch, CURLOPT_POST,true); 
						 curl_setopt($ch, CURLOPT_POSTFIELDS,$params);break;
			case "PUT" : curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, "PUT"); 
						 curl_setopt($ch, CURLOPT_POSTFIELDS,$params);break;
			case "DELETE":curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, "DELETE"); 
						  curl_setopt($ch, CURLOPT_POSTFIELDS,$params);break;
		}
		curl_exec($ch);
		curl_close($ch);
	}

	/**
	 * [postMultiExec description]
	 *  uee curl_multi_exec
	 */
	function postMultiExec($url_array,$data){

		$handles = $contents = array(); 
		 
		//init curl multi obj
		$mh = curl_multi_init();
		 
		//add curl handles
		$params = json_encode($data);
		foreach($url_array as $obj)
		{

			$key = $obj['ip'];
		    $handles[$key] = curl_init($obj['url']);

		    curl_setopt($handles[$key], CURLOPT_HTTPHEADER, array('Expect:','Content-type: text/json'));
		    curl_setopt($handles[$key], CURLOPT_RETURNTRANSFER, 1);
		    //time out
			curl_setopt($handles[$key], CURLOPT_CONNECTTIMEOUT, 5);
			curl_setopt($handles[$key], CURLOPT_TIMEOUT, 5);

			//ssl
			curl_setopt($handles[$key], CURLOPT_SSL_VERIFYPEER, false);
        	curl_setopt($handles[$key], CURLOPT_SSL_VERIFYHOST, false);
		    
		    //method & data
		    curl_setopt($handles[$key], CURLOPT_POST,true); 
			curl_setopt($handles[$key], CURLOPT_POSTFIELDS,$params);

		    curl_multi_add_handle($mh, $handles[$key]);
		}
		 
		//======================exec=================================
		$active = null;
		do {
		    $mrc = curl_multi_exec($mh, $active);
		} while ($mrc == CURLM_CALL_MULTI_PERFORM);
		 
		 
		while ($active and $mrc == CURLM_OK) {
		    
		    if(curl_multi_select($mh) === -1){
		        usleep(100);
		    }
		    do {
		        $mrc = curl_multi_exec($mh, $active);
		    } while ($mrc == CURLM_CALL_MULTI_PERFORM);
		 
		}
		//====================================================================
		 
		//get returnContent
		foreach($handles as $i => $ch)
		{
		    $content = curl_multi_getcontent($ch);
		    $contents[$i] = curl_errno($ch) == 0 ? json_decode($content,true) : array();
		}
		 
		//remove handle
		foreach($handles as $ch)
		{
		    curl_multi_remove_handle($mh, $ch);
		}
		 
		//close
		curl_multi_close($mh);

		return $contents;
	}


}

?>