<?php

/**
*	return true: restart rogue ap process success
    return false: restart rogue ap process fail
**/
function restartRogueApProcess(){
	$cmdStop = "/etc/init.d/rogueap stop";
	exec($cmdStop, $output, $return_stop);
	$cmdStart = "/etc/init.d/rogueap start";
	exec($cmdStart, $output, $return_start);

	if((0 === $return_stop) && (0 === $return_start)){
		return true;
	}else{
		return false;
	}
}

/**
*	get suppress switch
**/
$app->get(
    '/rogueApSwitch',
    function (){
    	$cmd = "uci get rogueap.RogueAP.SuppressSwitch; rogueap -x black_switch";
        $last_line = exec($cmd, $lines, $return_cmd);
        //echo "return_cmd:".$return_cmd." last_line:".$last_line;

		if(0 === $return_cmd){
			sscanf($lines[0], "%d", $suppress);
			if(1 === $suppress){
				$suppressSwitch = true;
			}else{
				$suppressSwitch = false;
			}

			sscanf($lines[1], "%d", $black);
			if(1 === $black){
				$blackSwitch = true;
			}else{
				$blackSwitch = false;
			}

			$result = array(
						'suppressSwitch' => $suppressSwitch,
						'blackSwitch' => $blackSwitch);

			$response = array(
						'success' => true,
						'result' => $result);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get suppress fail!');
		}

		echo json_encode($response);
	}
);

/**
*	set suppress switch
**/
$app->put(
    '/suppressSwitch',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			if($requestParas->suppressSwitch){
				$suppressSwitch = 1;
			}else{
				$suppressSwitch = 0;
			}

			$cmd = "cluster-cfg set rogueap.RogueAP.SuppressSwitch=".$suppressSwitch;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartRogueApProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'rogueAp_edit_suppressSwitch_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'rogueAp_edit_suppressSwitch_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config suppressSwitch: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	set black switch
**/
$app->put(
    '/blackSwitch',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			if($requestParas->blackSwitch){
				$blackSwitch = 1;
			}else{
				$blackSwitch = 0;
			}

			$cmd = "rogueap -x black_switch=".$blackSwitch;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);

			if(0 === $return_cmd){
				$log_info = $cmd." result:success";
				exec("logger -t web -p 5 ".$log_info);

				$response = array(
							'success' => true,
							'msg' => 'rogueAp_edit_blackSwitch_success');

				$cmd = "cluster-cfg set rogueap.RogueAP.BlackSwitch=".$blackSwitch;
				//echo "cmd:".$cmd;
                exec($cmd);

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'rogueAp_edit_blackSwitch_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config blackSwitch: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

function getRogueApList($hapMac){
	$cmd_location = "cluster-cfg ".$hapMac." get system.sysinfo.location";
	$location = exec($cmd_location, $lines_location, $return_location);
	//echo "location:".$location."#";

	$cmd = "rogueap -x get_apinfo";
	exec($cmd, $lines, $return_cmd);
	//var_dump($lines);

	if(0 !== $return_cmd){
		return NULL;
	}

	foreach ($lines as $linenum => $line) {
		if(0 == $linenum){
			$key = sscanf($line,"%s %s %s %s %s %s %s %s %s %s");
		}else{
			$result[$linenum-1]["hapMac"] = $hapMac;
			$result[$linenum-1]["hapLocation"] = $location;
			$value = explode("\t",$line);

			$arrayLen = count($value);
			if(9 == $arrayLen){
				array_push($value, "");
			}

			$arrayLen = count($value);
			for($i=0; $i<$arrayLen; $i++){
				if((1 == $i) || (2 == $i) || (9 == $i)){
					continue;
				}

				$value[$i] = intval($value[$i]);
			}

			for($i=0; $i<$arrayLen; $i++){
				if(2 == $i){
					$result[$linenum-1][$key[$i]] = rtrim($value[$i], " ");
				}else if(9 == $i){
					$result[$linenum-1][$key[$i]] = explode(",",$value[$i]);
				}else{
					$result[$linenum-1][$key[$i]] = $value[$i];
				}
			}
		}
	}

	return $result;
}

/**
*	get rogue ap list
**/
$app->get(
    '/rogueAps/:mac',
    function ($mac){
    	$cmd = "uci get bg-s.bs.enable";
		$last_line = exec($cmd, $lines, $return_cmd);
		//echo "return_cmd:".$return_cmd." last_line:".$last_line;

		if(0 === $return_cmd){
			sscanf($last_line, "%d", $switchInt);
			if(1 === $switchInt){
				$result = getRogueApList($mac);
				if(NULL === $result){
					$response = array(
								'success' => false,
								'result' => 'get rogueAps fail!');
				}else{
					$response = array(
								'success' => true,
								'result' => $result);
				}
			}else{
				$response = array(
							'success' => false,
							'result' => "error2");
			}
		}else{
			$response = array(
						'success' => false,
						'result' => "error1");
		}

		echo json_encode($response);
	}
);

/**
*	get rogue ap white list
**/
$app->get(
    '/rogueApWhiteList',
    function (){
    	$cmd = "uci get rogueap.RogueAP.wildcard";
    	$last_line = exec($cmd, $lines, $return_cmd);

    	$whitelistNum = 0;
        $whitelist = array();
    	if(0 != strcmp($last_line, "")){
    		$array = explode(" ",$last_line);
			$unique_array = array_unique($array);
			$list = array_merge($unique_array);
			for($x=0; $x<count($list); $x++) {
			  $whitelist[$x] = array( 'whitelistMac' => $list[$x] );
			}
			$whitelistNum = count($whitelist);
    	}

    	$result = array(
						'whitelistNum' => $whitelistNum,
						'whitelist' => $whitelist);

		$response = array(
						'success' => true,
						'result' => $result);

		echo json_encode($response);
	}
);

/**
*	add rogue ap white list
**/
$app->post(
    '/rogueApWhiteList',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			$whitelistValue = strtolower($requestParas->whitelistValue);

			$whitelist = chop($whitelistValue,":*");
			//echo $whitelist;
			$cmd = "rogueap -x get_blacklist";
			exec($cmd, $lines, $return_cmd);
			if(0 === $return_cmd){
				foreach ($lines as $linenum => $line) {
					if($linenum > 0){
						if(0 == strncasecmp($whitelist, ltrim($line), strlen($whitelist))){
							$cmd_del = "rogueap -x del_blackmac=".ltrim($line);
							exec($cmd_del);

							$log_info = $cmd_del." result:success";
							exec("logger -t web -p 5 ".$log_info);
						}
					}
				}
			}

			$cmd = "cluster-cfg add_list rogueap.RogueAP.wildcard=".$whitelistValue;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartRogueApProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'rogueAp_add_whiteList_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'rogueAp_add_whiteList_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "add rogueApWhiteList: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	delete rogue ap white list
**/
$app->delete(
    '/rogueApWhiteList/:whitelistValue',
    function ($whitelistValue){
    	try{
    		$cmd = "cluster-cfg del_list rogueap.RogueAP.wildcard=".$whitelistValue;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartRogueApProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'rogueAp_delete_whiteList_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'rogueAp_delete_whiteList_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "delete rogueApWhiteList: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	get rogue ap dynamic black list
**/
$app->get(
    '/rogueApDynamicBlackList',
    function (){
    	$cmd = "rogueap -x get_blacklist";
    	exec($cmd, $lines, $return_cmd);

    	$blacklistNum = 0;
        $blacklist = array();
        if(0 === $return_cmd){
        	foreach ($lines as $linenum => $line) {
				if($linenum > 0){
					$blacklist[$blacklistNum] = array( 'blacklistMac' => ltrim($line) );
					$blacklistNum++;
				}
			}
        }

    	$result = array(
						'blacklistNum' => $blacklistNum,
						'blacklist' => $blacklist);

		$response = array(
						'success' => true,
						'result' => $result);

		echo json_encode($response);
	}
);

/**
*	delete rogue ap dynamic black list
**/
$app->delete(
    '/rogueApDynamicBlackList/:blacklistValue',
    function ($blacklistValue){
    	try{
    		$cmd_del = "rogueap -x del_blackmac=".$blacklistValue;
			//echo "cmd_del:".$cmd_del;
			exec($cmd_del, $output, $return_del);
			if(0 === $return_del){
				$log_info = $cmd_del." result:success";
				exec("logger -t web -p 5 ".$log_info);

				$cmd_add = "cluster-cfg add_list rogueap.RogueAP.wildcard=".$blacklistValue;
				//echo "cmd_add:".$cmd_add;
				exec($cmd_add, $output, $return_add);
				if(0 === $return_add){
					$log_info = $cmd_add." result:success";
				}else{
					$log_info = $cmd_add." result:fail";
				}
				exec("logger -t web -p 5 ".$log_info);
			}else{
				$log_info = $cmd_del." result:fail";
				exec("logger -t web -p 5 ".$log_info);
			}

			$return_restart = restartRogueApProcess();

			if((0 === $return_del) && (0 === $return_add) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'rogueAp_delete_blackList_success');
			}else{
				$response = array(
							'success' => false,
							'msg' => 'rogueAp_delete_blackList_fail');
			}

			echo json_encode($response);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "delete rogueApDynamicBlackList: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

?>