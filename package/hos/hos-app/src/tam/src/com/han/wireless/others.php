<?php

/**
*	return true: restart backgroup scanning process success
    return false: restart backgroup scanning process fail
**/
function restartBackgroupScanningProcess(){
	$cmdReload = "/etc/init.d/bg-s reload";
	exec($cmdReload, $output, $return_reload);

	if(0 === $return_reload){
		return true;
	}else{
		return false;
	}
}

/**
*	get backgroup scanning
**/
$app->get(
    '/backgroupScanning',
    function (){
    	$cmd = "uci get bg-s.bs.enable; uci get bg-s.bs.scan_interval; uci get bg-s.bs.foreign_ch_dur";
        exec($cmd, $lines, $return_cmd);
        //var_dump($lines);

		if(0 === $return_cmd){
			sscanf($lines[0], "%d", $switchInt);
			sscanf($lines[1], "%d", $scanIntervalInt);
			sscanf($lines[2], "%d", $foreignChannelDurationInt);
			if(1 === $switchInt){
				$switch = true;
			}else{
				$switch = false;
			}

			$result = array(
						'backgroupScanning' => $switch,
						'scanInterval' => $scanIntervalInt,
						'foreignChannelDuration' => $foreignChannelDurationInt);

			$response = array(
						'success' => true,
						'result' => $result);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get backgroup scanning fail!');
		}

		echo json_encode($response);
	}
);

/**
*	set backgroup scanning switch
**/
$app->put(
    '/backgroupScanningSwitch',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			if($requestParas->backgroupScanning){
				$switch = 1;
			}else{
				$switch = 0;
			}

			$cmd = "cluster-cfg set bg-s.bs.enable=".$switch;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartBackgroupScanningProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'other_wireless_edit_backgroupScanningSwitch_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'other_wireless_edit_backgroupScanningSwitch_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config backgroupScanningSwitch: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	set scan interval
**/
$app->put(
    '/scanInterval',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			$scanInterval = $requestParas->scanInterval;

			$cmd = "cluster-cfg set bg-s.bs.scan_interval=".$scanInterval;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartBackgroupScanningProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'other_wireless_edit_scanInterval_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'other_wireless_edit_scanInterval_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config scanInterval: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	set foreign channel duration
**/
$app->put(
    '/foreignChannelDuration',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			$foreignChannelDuration = $requestParas->foreignChannelDuration;

			$cmd = "cluster-cfg set bg-s.bs.foreign_ch_dur=".$foreignChannelDuration;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartBackgroupScanningProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'other_wireless_edit_foreignChannelDuration_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'other_wireless_edit_foreignChannelDuration_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config foreignChannelDuration: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	return true: restart band steering process success
    return false: restart band steering process fail
**/
function restartBandSteeringProcess(){
	$cmdReload = "/etc/init.d/lbd reload";
	exec($cmdReload, $output, $return_reload);

	if(0 === $return_reload){
		return true;
	}else{
		return false;
	}
}

/**
*	get band steering
**/
$app->get(
    '/bandSteering',
    function (){
    	$cmd = "cluster-cfg get lbd.config.Enable";
        exec($cmd, $lines, $return_cmd);
        //var_dump($lines);

		if(0 === $return_cmd){
			sscanf($lines[0], "%d", $switchInt);
			if(1 === $switchInt){
				$switch = true;
			}else{
				$switch = false;
			}

			$result = array('bandSteering' => $switch);

			$response = array(
						'success' => true,
						'result' => $result);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get band steering fail!');
		}

		echo json_encode($response);
	}
);

/**
*	set band steering
**/
$app->put(
    '/bandSteering',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			if($requestParas->bandSteering){
				$switch = 1;
			}else{
				$switch = 0;
			}

			$cmd = "cluster-cfg set lbd.config.Enable=".$switch;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartBandSteeringProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'other_wireless_edit_bandSteering_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'other_wireless_edit_bandSteering_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config bandSteering: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	return true: restart aware process success
    return false: restart aware process fail
**/
function restartAwareProcess(){
	$cmdReload = "/etc/init.d/um reload";
	exec($cmdReload, $output, $return_reload);

	if(0 === $return_reload){
		return true;
	}else{
		return false;
	}
}

/**
*	get aware
**/
$app->get(
    '/aware',
    function (){
    	$cmd = "cluster-cfg get usermgn.voiceaware.switch";
        exec($cmd, $lines, $return_cmd);
        //var_dump($lines);

		if(0 === $return_cmd){
			sscanf($lines[0], "%d", $switchInt);
			if(1 === $switchInt){
				$switch = true;
			}else{
				$switch = false;
			}

			$result = array('aware' => $switch);

			$response = array(
						'success' => true,
						'result' => $result);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get aware wireless fail!');
		}

		echo json_encode($response);
	}
);

/**
*	set aware
**/
$app->put(
    '/aware',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			if($requestParas->aware){
				$cmd = "cluster-cfg set usermgn.voiceaware.switch=1";
			}else{
				$cmd = "cluster-cfg set usermgn.voiceaware.switch=0";
			}
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartAwareProcess();

			if(0 === $return_cmd){
				$response = array(
							'success' => true,
							'msg' => 'other_wireless_edit_aware_success');

				$log_info = $cmd." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'other_wireless_edit_aware_fail');

				$log_info = $cmd." result:fail";
			}

			echo json_encode($response);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config aware: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

?>