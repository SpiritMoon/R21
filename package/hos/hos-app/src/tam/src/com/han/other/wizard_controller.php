<?php

/**
*	download certificate install guide
**/

function downloadCrtFile($filePath){
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
*wizard
**/
$app->post(
    '/other/wizard',
    function () use ($app){
    	try {
	    	$requestBody = $app->request()->getBody();		
			$requestParas = json_decode($requestBody);
			$username = $requestParas->username;
			$passwd = $requestParas->password;
			$countryCode = $requestParas->countryCode;
			$timezone = $requestParas->timezone;
			$city = $requestParas->city;
					
			//check
			if($passwd == null || $passwd ==''){
				$response = array(
							'success' => false,
							'msg' => 'Paramater is invalid!');	
				echo json_encode($response);
				return;
			}

			$cmd = "getrevnumber;";
			exec($cmd,$execOut_1,$return_var);
			if($return_var != 0 || $execOut_1[0] != 0){
				$response = array(
							'success' => false,
							'msg' => 'wizard_log_wizardCancelled');	
				echo json_encode($response);
				return;
			}
					
			//get lock
			$cmd = "cfglock;";
			exec($cmd,$execOut_2,$return_var);
			if($return_var != 0 || $execOut_2[0] != 'locked'){
				$response = array(
					'success' => false,
					'msg' => 'wizard_log_wizardAutomated');	
				echo json_encode($response);
				return;
			}

			//set password
			$cmd = 'cluster-cfg set system.'.$username.'.password='.$passwd.';';
			exec($cmd,$execOut_3);

			$log_info = 'wizard set Administrator password success';
			exec("logger -t web -p 5 \"".$log_info."\"");			

			//set country code
			if($countryCode != ''){
				$setcountry = 'config_wlan setcountry '.$countryCode.' /dev/null &';
				exec($setcountry);		
				exec("logger -t web -p 7 \"".$setcountry."\"");
				$log_info = 'wizard set country : '.$countryCode.' success';
				exec("logger -t web -p 5 \"".$log_info."\"");
			}


			//set timeZone
			if($city !="" && $timezone !=""){
				//$cmd = 'cluster-cfg set system.sysinfo.timezone='.$timezone.';';
				//$cmd = $cmd.' cluster-cfg set system.sysinfo.city='.$city.';';
				$cmd = "cluster-cfg set system.sysinfo.timezone='".$timezone."';";
                $cmd = $cmd." cluster-cfg set system.sysinfo.city='".$city."';";
				exec($cmd);
			}
			$reload = '/etc/init.d/system reload  > /dev/null &';
			exec($reload);

			exec("logger -t web -p 7 \"".$cmd."\"");
			$log_info = 'wizard set timezone : '.$timezone.', city : '.$city.' success';
			exec("logger -t web -p 5 \"".$log_info."\"");

			//add wlan
			$msg = "wizard success";
			$success = true;
			$return = addWlan($requestParas);
			if($return != 0 ){
				$success = false;
				$msg = "wizard_log_addWlan_fault";
			}
		
			//unlock
			exec("cfgunlock;");
					
			$response = array(
						'success' => $success,
						'msg' => $msg);				
			echo json_encode($response);	


			$log_info = 'wizard config finish - '.$response.msg;
			if($response.success){
				exec("logger -t web -p 5 \"".$log_info."\"");		
	        }else{
	        	exec("logger -t web -p 3 \"".$log_info."\"");		
	        }

        } catch(Exception $e) {
        	//unlock
			exec("cfgunlock;");

			$response = array(
						'success' => false,
						'msg' => $e->getMessage() );
			echo json_encode($response);
			$log_info = 'wizard error:'.$e->getMessage();
			exec("logger -t web -p 3 \"".$log_info."\"");		
        }	
    }
);

/**
*	download certificate file contain certificate and install guide
**/
$app->put(
    '/downloadCertificate',
    function(){
    	$fileName = $_GET['name'];
    	try{
    		$fileArray = array();
    		$filePath="/etc/cert/".$fileName;
			$result = downloadCrtFile($filePath);
			if($result){
				$log_info = "download ".$filePath." success!";
			}else{
				$response = array(
							'success' => false,
							'msg' => 'syslog_down_error_1');

				echo json_encode($response);

				$log_info = "/etc/cert/".$fileName." is not exist!";
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