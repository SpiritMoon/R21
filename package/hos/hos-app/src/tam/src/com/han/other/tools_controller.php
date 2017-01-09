<?php

/**
*tools
*{"HanletName":"WebView for OmniAccess AP","CompanyName":"HAN NETWORKS","SN":"11111114","DeviceModel":"AP101","MAC:34:E7:0B:CC:CC":"40","Country":"US","SoftwareName":"hap","SoftwareVersion":"2.1.0","HardwareVersion":"1.10","EssidPrefix":"cluster","ClusterDescribe":"HAP cluster","Website":"website not exist","Legal":"legal not exist"}
**/
$app->get(
    '/other/systemInfo',
    function (){
		$result = array();
		try {


			$cmd = "showsysinfo;";
			exec($cmd,$execOut);
			foreach($execOut as $v){
				$str = trim($v);//like this => Company Name:HAN NETWORKS
				$key = substr($str,0,strpos($str,':'));
				$vaule = substr($str,strpos($str,':')+1);		
				$result[str_replace(' ',"", $key)] = $vaule;
			}

			unset($execOut);
			$cmd = "uci get system.@system[0].hanletName;showver;cluster-cfg get wireless.wifi0.country;";
			exec($cmd,$execOut);
			$arraySize = count($execOut);
			$result['countryCode'] = $arraySize >=3?$execOut[2]:'';
			$result['SoftwareVer'] = $arraySize >=2?$execOut[1]:'';
			$result['HanletName'] = $arraySize >=1?$execOut[0]:'';

			$response = array(
						'success' => true,
						'result' => $result);	
			echo json_encode($response);		

        } catch(Exception $e) {
			$response = array(
				'success' => false,
				'msg' => 'showsysinfo fault!');	
			echo json_encode($response);
        }
    }
);

/**
 *tools
 */
$app->post(
    '/other/tools',
    function () use ($app) {
		
		try {
			$requestBody = $app->request()->getBody();		
			$obj = json_decode($requestBody);
			$command = $obj->command;
			$hostname = $obj->hostname;

			$cmd = 'tech_support_command '.$command;
			if($hostname != ''){
				$cmd = $cmd.' '.$hostname;
			}

			exec($cmd,$execOut);

			if($execOut == null ){
				$response = array(
							'success' => false,
							'result' => '');	
				echo json_encode($response);
				return;
			}

			$result ='';
			foreach ($execOut as $value) {
				$result = $result.$value."\r\n";
			}

			$response = array(
						'success' => true,
						'result' => $result);	
			echo json_encode($response);

		} catch(Exception $e) {
			$response = array(
							'success' => false,
							'result' => '');	
			echo json_encode($response);
		}

    }
);

$app->get(
    '/other/countryCode',
    function (){
		try {
			$countryFlag = getCountryFlag();
			$response = array(
				'success' => true,
				'countryFlag' => $countryFlag);	
			echo json_encode($response);

        } catch(Exception $e) {
			$error = array(
				'success' => false,
				'msg' => 'get countryCode fault!');	
			echo json_encode($error);
        }
    }
);
$app->get(
	'/other/pmdSwitch',
	function (){
		try {
			$cmd = 'uci get upload_core.upload_core.enable';
			exec($cmd,$execOut);
			if($execOut == null){
				$response = array(
							'success' => false,
							'result' => '');
				echo json_encode($response);
				return;
			}
			$result ='';
			foreach ($execOut as $value) {
				$result = $value;
			}
			$response = array(
						'success' => true,
						'result' => $result);
			echo json_encode($response);


		} catch (Exception $e){
			$error = array(
				'success' => false,
				'msg' => 'get switch status fault!'
			);
			echo json_encode($error);
		}
	}
);
$app->get(
	'/other/pmdIp',
	function (){
		try {
			$cmd = 'uci get upload_core.upload_core.server';
			exec($cmd,$execOut);
			if($execOut == null){
				$response = array(
							'success' => false,
							'result' => '');
				echo json_encode($response);
				return;
			}
			$result ='';
			foreach ($execOut as $value) {
				$result = $value;
			}
			$response = array(
						'success' => true,
						'result' => $result);
			echo json_encode($response);


		} catch (Exception $e){
			$error = array(
				'success' => false,
				'msg' => 'get switch status fault!'
			);
			echo json_encode($error);
		}
	}
);

$app->put(
	'/other/setPmdSwitch',
	function () use ($app){

    	$requestBody = $app->request()->getBody();
    	$requestParas = json_decode($requestBody);
    	$enable = $requestParas->enable;
    	if($enable){
    		$cmd = "cluster-cfg set upload_core.upload_core.enable=1";
    	}else {
			$cmd = "cluster-cfg set upload_core.upload_core.enable=0";
		}
		exec($cmd, $output, $return);
		if(0 == $return){
			$switchcmd = "ubus call system coredump_reload";
			exec($switchcmd, $switchoutput, $switchreturn);
			$logswitch = "ubus call remote_debug_log reload";
            exec($logswitch, $logoutput, $switchreturn);
			$response = array (
						'success' => true,
						'msg' => 'set pmd switch success! '

			);
			echo json_encode($response);

		}else {
			$response = array (
						'success' => false,
						'msg' => 'set pmd switch fault! '

			);
			echo json_encode($response);
		}
	}
);

$app->put(
	'/other/setPmdIp',
	function() use ($app){
    	$requestBody = $app->request()->getBody();
    	$requestParas = json_decode($requestBody);
    	$pmdIp = $requestParas->pmdIp;
		$cmd = "cluster-cfg set upload_core.upload_core.server=".$pmdIp;
		exec($cmd, $output, $return);
		if(0 == $return){
			$switchcmd = "ubus call system coredump_reload";
			exec($switchcmd, $switchoutput, $switchreturn);

			$logswitch = "ubus call remote_debug_log reload";
			exec($logswitch, $logoutput, $switchreturn);

			$response = array (
						'success' => true,
						'msg' => 'set pmd IP success! '

			);
			echo json_encode($response);

		}else {
			$response = array (
						'success' => false,
						'msg' => 'set pmd IP fault! '

			);
			echo json_encode($response);
		}
	}
);
$app->get(
    '/other/city',
    function (){
		try {
			$cmd = "uci get system.sysinfo.city";
			exec($cmd, $output);
			$result ='';
			foreach ($output as $value) {
				$result = $value;
			}
			$response = array(
				'success' => true,
				'city' => $result);
			echo json_encode($response);

        } catch(Exception $e) {
			$error = array(
				'success' => false,
				'msg' => 'get city fault!');
			echo json_encode($error);
        }
    }
);

?>
