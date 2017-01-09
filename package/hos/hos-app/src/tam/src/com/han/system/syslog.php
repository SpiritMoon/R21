<?php

/**
*	return true: restart syslog process success
    return false: restart syslog process fail
**/
function restartSyslogProcess(){
	$cmd = "/etc/init.d/log reload";
	exec($cmd, $output, $return);

	if(0 === $return){
		return true;
	}else{
		return false;
	}
}

/**
*	get syslog statistics
**/
$app->get(
	'/syslogStatistics',
	function() use ($app){
		$host = $app->request()->getHost();
        $errNum=0;
        $critNum=0;
        $alertNum=0;
        $emergNum=0;

		$cmd = "cat /proc/kes_syslog | egrep '[.]err' | wc -l; cat /proc/kes_syslog | egrep '[.]crit' | wc -l; cat /proc/kes_syslog | egrep '[.]alert' | wc -l; cat /proc/kes_syslog | egrep '[.]emerg' | wc -l";
		//echo "cmd:".$cmd;
		exec($cmd, $lines, $return_cmd);
		//var_dump($lines);

		if(0 === $return_cmd){
			sscanf($lines[0], "%d", $errNum);
			sscanf($lines[1], "%d", $critNum);
			sscanf($lines[2], "%d", $alertNum);
			sscanf($lines[3], "%d", $emergNum);
		}

		$result = array(
					'source' => $host,
					'errSyslogNum' => $errNum,
					'critSyslogNum' => $critNum,
					'alertSyslogNum' => $alertNum,
					'emergSyslogNum' => $emergNum);

		$response = array(
					'success' => true,
					'result' => $result);

		echo json_encode($response);
	}
);

/**
*	get syslog list
**/
$app->get(
	'/syslog',
	function() use ($app){
		$host = $app->request()->getHost();

		$prio = "'[.]err |[.]crit |[.]alert |[.]emerg'";
		$cmd = "fgrep _GOLSOH_ /proc/kes_syslog|awk -F '_GOLSOH_'  '{print $1 $2}'| egrep ".$prio;
		//echo "cmd:".$cmd;
		exec($cmd, $lines, $return_cmd);
		//var_dump($lines);

		if(0 === $return_cmd){
			$syslogList = array();
			$index = 0;

			foreach ($lines as $linenum => $line){
				$title="";
                $level="";
                $time="";

                if(0 !== strcmp("", $line)){
					$pos = strpos($line, ".");
					$contentTime = substr($line, 0, $pos);
                    $posTime = strrpos($contentTime, " ");
                    $time = substr($line,0, $posTime);
					$content = substr($line, $pos+1);
					$tem_array = explode(" ", $content);
					$level = $tem_array[0];
					//echo "level:".$level."#";
					$pos = strpos($content, ":");
					$title = substr($content, $pos+2);
					//echo "title:".$title."#";
				}

				$syslog = array(
							'title' => $title,
							'level' => $level,
							'source' => $host,
							'time' => $time);

				$syslogList[$index] = $syslog;
				$index++;
			}


			$response = array(
						'success' => true,
						'result' => $syslogList);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get syslog fail!');
		}

		echo json_encode($response);
	}
);

/**
*	get log remote switch
**/
$app->get(
    '/syslogServerPara',
    function (){
    	$cmd = "cluster-cfg get system.@system[0].log_remote; cluster-cfg get system.@system[0].log_ip; cluster-cfg get system.@system[0].log_priority";
        exec($cmd, $lines, $return_cmd);
        //var_dump($lines);

		if(0 === $return_cmd){
			sscanf($lines[0], "%d", $logRemoteSwitchInt);
			if(1 === $logRemoteSwitchInt){
				$logRemoteSwitch = true;
			}else{
				$logRemoteSwitch = false;
			}

			$result = array(
						'logRemoteSwitch' => $logRemoteSwitch,
						'ip' => $lines[1],
						'level' => $lines[2]);

			$response = array(
						'success' => true,
						'result' => $result);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get log remote fail!');
		}

		echo json_encode($response);
	}
);

/**
*	edit syslog server
**/
$app->put(
    '/syslogServerLevel',
    function() use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			$level = $requestParas->level;

			$cmd = "cluster-cfg set system.@system[0].log_priority=".$level;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartSyslogProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'syslog_edit_level_success');

				$log_info = "config syslog priority:".$level." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_edit_level_fail');

				$log_info = "config syslog priority:".$level." result:fail";
			}

			echo json_encode($response);
			exec("logger -t web -p 7 \"".$cmd."\"");
			exec("logger -t web -p 5 \"".$log_info."\"");
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config syslogServerLevel error: ".$e->getMessage();
			exec("logger -t web -p 3 \"".$log_info."\"");
		}
	}
);

/**
*	edit log remote switch
**/
$app->put(
    '/logRemoteSwitch',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			if($requestParas->logRemoteSwitch){
				$logRemoteSwitch = 1;
			}else{
				$logRemoteSwitch = 0;
			}

			$cmd = "cluster-cfg set system.@system[0].log_remote=".$logRemoteSwitch;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);

			if(0 === $return_cmd){
				$response = array(
							'success' => true,
							'msg' => 'syslog_edit_remoteSwitch_success');

				$log_info = "config syslog remote switch:".$logRemoteSwitch." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_edit_remoteSwitch_fail');

				$log_info = "config syslog remote switch:".$logRemoteSwitch." result:fail";
			}

			echo json_encode($response);
			exec("logger -t web -p 7 \"".$cmd."\"");
			exec("logger -t web -p 5 \"".$log_info."\"");

			restartSyslogProcess();
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config logRemoteSwitch error: ".$e->getMessage();
			exec("logger -t web -p 3 \"".$log_info."\"");
		}
	}
);

/**
*	edit syslog server
**/
$app->put(
    '/syslogServerIp',
    function() use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			$ip = $requestParas->ip;

			$cmd = "cluster-cfg set system.@system[0].log_ip=".$ip;
			//echo "cmd:".$cmd;
			exec($cmd, $output, $return_cmd);
			$return_restart = restartSyslogProcess();

			if((0 === $return_cmd) && ($return_restart)){
				$response = array(
							'success' => true,
							'msg' => 'syslog_edit_serverIp_success');

				$log_info = "config syslog remote Server:".$ip." result:success";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_edit_serverIp_fail');

				$log_info = "config syslog remote Server:".$ip." result:fail";
			}

			echo json_encode($response);
			exec("logger -t web -p 7 \"".$cmd."\"");
			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config syslogServerIp: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

function downloadFile($fileName){
	$filePath="/tmp/".$fileName;

	if(file_exists($filePath)){
		$fileSize = filesize($filePath);
		$file = fopen($filePath, "r");

		header("Content-type: application/octet-stream");
		header("Accept-Ranges: bytes");
		header("Accept-Length: ".$fileSize);
		//header("Content-Disposition: attachment; filename=".$fileName);

		if($fileSize>0){
		    echo fread($file, $fileSize);
	            fclose($file);
	            return true;
		}
		return false;
	}
	return false;
}

/**
*	download syslog /proc/kes_syslog
**/
$app->put(
    '/downloadSyslog1',
    function(){
    	try{
    		$fileName = "kes_syslog";
    		$filePath="/tmp/".$fileName;
			exec("fgrep _GOLSOH_ /proc/".$fileName." |awk -F _GOLSOH_ '{print $1 $2}'>".$filePath);
    		//exec("cp /proc/".$fileName." ".$filePath);

			$result = downloadFile($fileName);
			if($result){
				$log_info = "download ".$filePath." success!";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_down_error_1');

				echo json_encode($response);

				$log_info = "/proc/".$fileName." is not exist!";
			}

			exec("rm ".$filePath);

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "downloadSyslog: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	download syslog /tmp/kes_history_syslog.log
**/
$app->put(
    '/downloadSyslog2',
    function(){
    	try{
			$fileName = "kes_history_syslog.log";
			$fileNameDemo = "kes_history_syslog_demo.log";
			$filePath="/tmp/kes_history_syslog_demo.log";
			exec("fgrep _GOLSOH_ /tmp/".$fileName." |awk -F _GOLSOH_ '{print $1 $2}'>".$filePath);
			$result = downloadFile($fileNameDemo);
			if($result){
				$log_info = "download ".$filePath." success!";
				exec("rm ".$filePath);
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_down_error_2');

				echo json_encode($response);

				$log_info = $filePath." is not exist!";
			}

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "downloadSyslog: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

/**
*	download syslog /tmp/kes_history_traps.log
**/
$app->put(
    '/downloadSyslog3',
    function(){
    	try{
			$fileName = "kes_history_traps.log";
			$filePath="/tmp/".$fileName;

			$result = downloadFile($fileName);
			if($result){
				$log_info = "download ".$filePath." success!";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_down_error_3');

				echo json_encode($response);

				$log_info = $filePath." is not exist!";
			}

			exec("logger -t web -p 5 ".$log_info);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "downloadSyslog: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

?>