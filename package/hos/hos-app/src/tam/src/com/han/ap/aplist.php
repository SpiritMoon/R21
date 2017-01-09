<?php

/*get ap list*/
function aplist(){
	$cmd="show_cluster";
	$last_line=exec($cmd,$lines,$ret_err);
	if($ret_err){
		return -1;
	}
	foreach ($lines as $linenum=>$line) {
		$table[$linenum]=preg_split("/[ ]+/", $line);
		if($linenum>0){
			foreach ($table[$linenum] as $key => $value)
				$retdata[$linenum-1][$table[0][$key]]=$value;
			}
	}
	return $retdata;

}

function MaskInt2IP($num){
	$inter_str = "";
	for($i=0;$i<$num;$i++){
		$inter_str=$inter_str."1";
	}
	for($i=$num;$i<32;$i++){
		$inter_str=$inter_str."0";
	}
	return long2ip(bindec($inter_str));
}

$app->get(
	'/checkstate',
	function () use ($app){
		$response=array(
			'success'=>true,
			'result'=>"reboot successfully"
		);
		echo json_encode($response);
	});

$app->get(
	'/pvcinfo',
	function () use ($app){
		$cmd = "cluster_mgt -x show=pvc";
		$last_line=exec($cmd,$lines,$ret_err);
        if(!$ret_err){
			$pvcInfo=preg_split("/[ ]+/", $lines[1]);
			$response=array(
				'success'=>true,
				'result'=>$pvcInfo[0]
			);
        }else{
			$response=array(
				'success'=>false,
				'result'=>"failed"
			);
        }




		echo json_encode($response);
	});

/*ap list*/
$app->get(
	'/haps',
	function (){
		try {
			$retlist=aplist();
			if($retlist == -1){
					$response=array(
							'success'=>false,
							'result'=>$retlist
					);
				}else{
					$response=array(
						'success'=>true,
						'result'=>$retlist
					);
				}
			echo json_encode($response);
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => 'get AP list error');
        	echo json_encode($error);
        }
	});

$app->get(
	'/getapname',
	function () use ($app){
		$result_array = array();
		$mac_cmd="showsysinfo | grep  -E 'MAC'";
		$last_line=exec($mac_cmd,$lines,$ret_err);
		if($ret_err){
			$response=array(
				'success'=>false,
				'result'=>"cannot get mac"
			);
			echo json_encode($response);
			return;
		}else{
			$tmp=explode(":", $last_line,2);
			$result_array["mac"]= $tmp[1];
			$cmd_name = "cluster-cfg ".$tmp[1]." get system.sysinfo.hostname";
			$last_line=exec($cmd_name,$lines,$ret_err);
			if($ret_err){
				$result_array["apname"] = "";
			}else{
				$result_array["apname"] = $last_line;
			}
			$response=array(
				'success'=>true,
				'result'=>$result_array
			);
			echo json_encode($response);
		}
	});



/*ap led  status*/
$app->get(
	'/ledstatus',
	function (){
		try {
			$cmd = " ubus call ledctrl status";
			$status=0;
			$last_line=shell_exec($cmd);
			$last_line = preg_replace('/[\n\t"\s+{}]/','',$last_line);
			$array=explode(":",$last_line);
			switch($array[0]){
				case "night_mode":
					$status = 0;
					break;
				case "default_mode":
					$status = 1;
					break;
				case "blink":
					$status = 2;
					break;
				default:
					$status = 0;
					break;
			}

			$response=array(
				'success'=>true,
				'result'=>$status
			);
			echo json_encode($response);
		}catch(Exception $e) {
			$error = array(
						'success' => false,
						'msg' => 'get status of the ap error');
			echo json_encode($error);
		}
	});

/*get sys info*/
$app->get(
		'/baseinfo',
		function(){
			try {
				$ip_flag=false;
				$ip_address_flag=false;
				$ip_mask_flag=false;
				$route_flag=false;
				$move=array("\""," ",",","\t");
				$cmd="ubus call network.interface.wan status";

				exec($cmd,$lines,$ret_err);
				for($i=0; $i<count($lines); $i++)
				{
					$search = strripos($lines[$i],"ipv4-address");
					if((!is_bool($search))&&(!$ip_flag)){
						$inter = $i+1;
						for($inter; $inter<count($lines); $inter++)
						{
							$search_ip = strripos($lines[$inter],"address");
							if((!is_bool($search_ip))&&(!$ip_address_flag)){
								$ip_str = $lines[$inter];
								$ip_address_flag = true;
							}
							$search_mask = strripos($lines[$inter],"mask");
							if((!is_bool($search_mask)) && (!$ip_mask_flag)){
								$mask_str = $lines[$inter];
								$ip_mask_flag = true;
							}
							if($ip_mask_flag && $ip_address_flag)
							{
								break;
							}
						}
						$ip_flag = true;
					}
					$search1 = strripos($lines[$i],"route");
					if((!is_bool($search1)) && (!$route_flag)){
						$inter = $i+1;
						for($inter; $inter<count($lines); $inter++)
						{
							$search_gateway = strripos($lines[$inter],"nexthop");
							if(!is_bool($search_gateway)){
								$gateway_str =  $lines[$inter];
								$route_flag = true;
							}
						}
					}
					if($ip_flag && $route_flag){
						break;
					}
				}
				$tmp=explode(":", $ip_str,2);
				$ip_str=str_replace($move, '', $tmp[1]);
				$tmp=explode(":", $gateway_str,2);
				$gateway_str=str_replace($move, '', $tmp[1]);
				$tmp=explode(":", $mask_str,2);
				$mask_str=intval(str_replace($move, '', $tmp[1]));
				$mask_str = MaskInt2IP($mask_str);

				$result_array = array();
				$result_key=array("SN","Model","mac","Firmware","netproto","ip","gateway","netmask","apName","apLoc","uploadtime","uploadflag");
				$cmd_baseinfo="showsysinfo | grep  -E '";
				$cmd_ip_info="uci get network.wan.proto";
				$cmd_key=array("SN'","Model'","MAC'");
				for($i=0;$i<count($cmd_key);$i++)
				{
					$key = $result_key[$i];
					$cmd=$cmd_baseinfo.$cmd_key[$i];
					$last_line=exec($cmd,$lines,$ret_err);
					if($ret_err){
						$result_array[$key] = "";
					}else{
						$tmp=explode(":", $last_line,2);
						$result_array[$key] = $tmp[1];
					}
				}
				$cmd_verion="showver";
				$result_array["Firmware"]=exec($cmd_verion);
				$last_line=exec($cmd_ip_info,$lines,$ret_err);
				if($ret_err){
					$result_array[$result_key[4]] = "";
				}else{
					$result_array[$result_key[4]] = $last_line;
				}
				$cmd_name="cluster-cfg ".$result_array["mac"]." get system.sysinfo.hostname";
				$last_line=exec($cmd_name,$lines,$ret_err);
				if($ret_err){
					$result_array[$result_key[8]] = "";
				}else{
					$result_array[$result_key[8]] = $last_line;
				}

				$cmd_location="cluster-cfg ".$result_array["mac"]." get system.sysinfo.location";
				$last_line=exec($cmd_location,$lines,$ret_err);
				if($ret_err){
					$result_array[$result_key[9]] = "";
				}else{
					$result_array[$result_key[9]] = $last_line;
				}

				$result_array[$result_key[5]]=$ip_str;
				$result_array[$result_key[6]]=$gateway_str;
				$result_array[$result_key[7]]=$mask_str;

				$cmd_upload_info="cat /etc/cfm/upgrade-tag ";
				$last_str = exec($cmd_upload_info,$upinfo_array,$info_err);
				if($info_err){
					$result_array[$result_key[10]]=" ";
					$result_array[$result_key[11]]="1";
				}else{
					$upinfo = explode("@", $last_str,2);
					if(count($upinfo) == 2){
						$result_array[$result_key[10]]=$upinfo[1];
						$result_array[$result_key[11]]=$upinfo[0];
					}else{
						$result_array[$result_key[10]]=" ";
						$result_array[$result_key[11]]="1";
					}
				}
				
				$response=array(
						'success'=>true,
						'result'=>$result_array
					);
				echo json_encode($response);
			}catch(Exception $e) {
				$error = array(
							'success' => false,
							'msg' => 'get baseinfo of the ap error');
				echo json_encode($error);
			}
		});

/*get current cfg*/
$app->get(
	'/currentcfg',
	function (){
		try {
			$filepath="/tmp/cluster.conf";
			$cmd="cfgupld";
			$ret = shell_exec($cmd);
			if(!strcmp($ret,"done")){
				$response=array(
					'success'=>false,
					'result'=>"failed"
				);
			}else{
				$body = file_get_contents($filepath);
				$response=array(
					'success'=>true,
					'result'=>$body
				);
			}
			echo json_encode($response);
        }catch(Exception $e) {
        	$error = array(
				'success' => false,
				'msg' => 'get configuration of the ap error');
        	echo json_encode($error);
        }
	});

/*reboot one ap*/
$app->put(
	'/reboot',
	function (){
		try {
			$cmd_flag="/usr/sbin/reset_reason add 06";
			shell_exec($cmd_flag);
			$cmd="reboot";
			$last_line=exec($cmd,$out,$ret_err);
			if($ret_err){
				$response=array(
					'success'=>false,
					'result'=>"reboot failed !"
				);
				$log_info = "reboot failed !";
			}else{
				$response=array(
					'success'=>true,
					'result'=>"reboot successfully"
				);
				$log_info ="reboot successfully !";
			}
			echo json_encode($response);
			exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => 'reboot ap error');
        	echo json_encode($error);
        	$log_info = "reboot ap error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
	});

/*set ap name*/
$app->put(
	'/chgapname',
	function() use($app){
		try {
			$requestBody=$app->request()->getBody();
			$requestJson=json_decode($requestBody);
			$cmd="cluster-cfg ".$requestJson->mac." set system.sysinfo.hostname=".$requestJson->apname;
			exec($cmd,$out,$ret_err);
				if($ret_err){
					$response=array(
						'success'=>false,
						'result'=>$ret_err
					);
					$log_info ="modify the name of the AP to ".$requestJson->apname." failed";
				}else{
					$response=array(
						'success'=>true,
						'result'=>"success"
					);
					$log_info ="modify the name of the AP to ".$requestJson->apname." successfully";
				}
			echo json_encode($response);
			exec("logger -t web -p 5 \"".$log_info."\"");
		}catch(Exception $e) {
			$error = array(
				'success' => false,
				'msg' => 'modify the name of the AP error');
			echo json_encode($error);
			$log_info = "modify the name of the AP error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
		}
	});

/*set ap location*/
$app->put(
	'/chgaploc',
	function() use($app){
		try {
			$requestBody=$app->request()->getBody();
			$requestJson=json_decode($requestBody);
			$cmd="cluster-cfg ".$requestJson->mac." set system.sysinfo.location=".$requestJson->aploc;
			exec($cmd,$out,$ret_err);
					if($ret_err){
						$response=array(
							'success'=>false,
							'result'=>$ret_err
						);
						$log_info ="modify the location of the ap to ".$requestJson->aploc." failed";
					}else{
						$response=array(
							'success'=>true,
							'result'=>"success"
						);
						$log_info ="modify the location of the ap to ".$requestJson->aploc." successfully";
					}
			echo json_encode($response);
			exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => 'modify the location of the ap error');
        	echo json_encode($error);
        	$log_info = "modify the location of the ap error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
	});

/*auth ap joining to work*/
$app->put(
		'/toauth',
		function() use($app){
			try {
				$requestBody=$app->request()->getBody();
				$requestJson=json_decode($requestBody);
				$cmd="cluster_cli  auth  ".$requestJson->mac;
				$last_line=exec($cmd,$lines,$ret_err);
				if($ret_err){
					$response=array(
						'success'=>false,
						'result'=>$ret_err
					);
					$log_info ="the ap which mac is ".$requestJson->mac." joining the Group failed !";
				}else{
					$response=array(
						'success'=>true,
						'result'=>$ret_err
					);
					$log_info ="the ap which mac is ".$requestJson->mac." joining the Group successfuly !";
				}
				echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
				exec("logger -t web -p 5 \"".$log_info."\"");
            }catch(Exception $e) {
            	$error = array(
            		'success' => false,
            		'msg' => 'accept ap  error');
            	echo json_encode($error);
            	$log_info = "the ap which mac is ".$requestJson->mac." access the Group error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
            }
});

/*kick off ap */
$app->put(
		'/kickoffap',
		function() use($app){
			try {
				$requestBody=$app->request()->getBody();
    			$requestJson=json_decode($requestBody);
    			$cmd="cluster_cli  unauth  ".$requestJson->mac;
    			$last_line=exec($cmd,$lines,$ret_err);
    			if($ret_err){
    				$response=array(
    					'success'=>false,
    					'result'=>$ret_err
    				);
    				$log_info ="kick the ap which mac is ".$requestJson->mac." out of the Group failed !";
    			}else{
    				$response=array(
    					'success'=>true,
    					'result'=>$ret_err
    				);
    				$log_info ="kick the ap which mac is ".$requestJson->mac." out of the Group successfully !";
    			}
    			echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
    			exec("logger -t web -p 5 \"".$log_info."\"");
			}catch(Exception $e) {
				$error = array(
					'success' => false,
					'msg' => 'kickoff the ap error');
				echo json_encode($error);
				$log_info = "kick the ap which mac is ".$requestJson->mac." out of the Group error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
			}
});

/*delete ap */
$app->put(
		'/deleteap',
		function() use($app){
			try {
				$requestBody=$app->request()->getBody();
    			$requestJson=json_decode($requestBody);
    			$cmd="cluster_cli  del    ".$requestJson->mac;
    			$last_line=exec($cmd,$lines,$ret_err);
    			if($ret_err){
    				$response=array(
    					'success'=>false,
    					'result'=>$ret_err
    				);
    				$log_info ="delete the ap which mac is ".$requestJson->mac." from the group failed !";
    			}else{
    				$response=array(
    					'success'=>true,
    					'result'=>$ret_err
    				);
    				$log_info ="delete the ap which mac is ".$requestJson->mac." from the group successfully !";
    			}
    			echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
    			exec("logger -t web -p 5 \"".$log_info."\"");
			}catch(Exception $e) {
				$error = array(
					'success' => false,
					'msg' => 'delete the ap error');
				echo json_encode($error);
				$log_info = "delete the ap which mac is ".$requestJson->mac." from the group error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
			}
});

/*set ap priority*/
$app->put(
	'/prioritychange',
	function() use($app){
		try {
			$requestBody=$app->request()->getBody();
    		$requestJson=json_decode($requestBody);
    		$mac=$requestJson->mac;
    		$cmd="cluster-cfg set cluster.cluster.cluster_priority=".$mac;
    		$last_line=exec($cmd,$out,$ret_err);
    		if($ret_err){
    			$response=array(
    				'success'=>false,
    				'result'=>$ret_err
    			);
    			$log_info ="set cluster_priority=".$mac." failed !";
    		}else{
    			$response=array(
    				'success'=>true,
    				'result'=>$ret_err
    			);
    			$log_info ="set cluster_priority=".$mac." successfully !";
    		}
    		echo json_encode($response);
			exec("logger -t web -p 7 \"".$cmd."\"");
    		exec("logger -t web -p 5 \"".$log_info."\"");
		}catch(Exception $e) {
			$error = array(
				'success' => false,
				'msg' => 'modify the priority of the ap error');
			echo json_encode($error);
			$log_info = "set cluster_priority=".$mac." error :".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
		}
});
/*set ip/netmask/gateway */
$app->put(
		'/chgnetaddr',
		function() use($app){
			try {
    			$inter =";";
    			$requestBody=$app->request()->getBody();
    			$requestJson=json_decode($requestBody);
    			$mac = strtoupper($requestJson->mac);
    			$proto = strtoupper($requestJson->proto);
    			$set_key=array("proto=","ipaddr=","netmask=","gateway=","dhcp","static");
    			$cmd_base="cluster-cfg ".$mac." set network.wan.";
    			if(!strcmp($proto,"STATIC")){
    				$cmd_proto = $cmd_base.$set_key[0].$set_key[5];
    				$cmd_ip = $cmd_base.$set_key[1].$requestJson->ipaddr;
    				$cmd_netmask = $cmd_base.$set_key[2].$requestJson->netmask;
    				$cmd_gateway = $cmd_base.$set_key[3].$requestJson->gateway;
    				$cmd = $cmd_proto.$inter.$cmd_ip.$inter.$cmd_netmask.$inter.$cmd_gateway.$inter;
    				exec($cmd,$out,$ret_err);
    				$log_info ="modify AP ip:".$requestJson->ipaddr.",netmask:".$requestJson->netmask.",gateway:".$requestJson->gateway;
    				exec("logger -t web -p 5 \"".$log_info."\"");
    			}else{
    				$cmd_base_dele="cluster-cfg ".$mac." delete network.wan.";
    				$cmd_pro = $cmd_base.$set_key[0].$set_key[4];
    				$cmd_dele_ip = $cmd_base_dele."ipaddr";
    				$cmd_dele_netmask = $cmd_base_dele."netmask";
    				$cmd_dele_gateway = $cmd_base_dele."gateway";
    				$cmd=$cmd_pro.$inter.$cmd_dele_ip.$inter.$cmd_dele_netmask.$inter.$cmd_dele_gateway.$inter;
    				exec($cmd,$out,$ret_err);
    			}
				
    			$response=array(
    				'success'=>true,
    				'result'=>"success"
    			);
    			$log_info ="modify AP ip mode to ".$proto." successfully !";
    			echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
    			exec("logger -t web -p 5 \"".$log_info."\"");
            }catch(Exception $e) {
            	$error = array(
            		'success' => false,
            		'msg' => 'modify ip info of the ap error');
            	echo json_encode($error);
            	$log_info = "modify ip info of the ap error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
            }
});
$app->get(
	'/reload',
	function (){
		try {
    		$reload = 'ubus call network reload';
    		exec($reload);
    		$vipcmd = 'vip_cfg';
    		exec($vipcmd);
    		$response=array(
    			'success'=>true,
    			'result'=>"success"
    		);
    		echo json_encode($response);
    		$log_info = "restart network successfully !";
			exec("logger -t web -p 7 \"".$reload."\"");
            exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => 'restart network error');
        	echo json_encode($error);
        	$log_info = "restart network error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
	});

/*clear all cfg*/
$app->put(
	'/clearallcfg',
	function (){
		try {
    		$cmd="cfgclr";
    		$ret = shell_exec($cmd);
    		$response=array(
    			'success'=>true,
    			'result'=>"cfgclr_suc"
    			);
			$log_info = "clear configration of the ap successfully !";
			exec("logger -t web -p 7 \"".$cmd."\"");
			exec("logger -t web -p 5 \"".$log_info."\"");
    		echo json_encode($response);
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => 'cfgclr_error');
        	echo json_encode($error);
        	$log_info = "clear configration of the ap error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
	});
/*backup all cfg*/
$app->get(
	'/backupcfg',
	function (){
		try {
    		$cmd="cfgupld";
    		$ret = shell_exec($cmd);
    		if(!strcmp($ret,"done")){
				$log_info = "backup configration of ap failed !";
				exec("logger -t web -p 5 \"".$log_info."\"");
    			return -1;
    		}
    		$FileName="cluster.conf";
    		$filepath="/tmp/".$FileName;
    		$FileSize=filesize($filepath);
    		$file = fopen($filepath, "r");

    		header("Content-type: application/octet-stream");

      		header("Accept-Ranges: bytes");//按照字节大小返回

      		header("Accept-Length: $FileSize");//返回文件大小

     		header("Content-Disposition: attachment; filename=".$FileName);

     		echo fread($file, filesize($filepath));
     		fclose($file);
			$log_info = "backup configration of ap successfully !";
			exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => 'backup the configration of ap error');
        	echo json_encode($error);
        	$log_info = "backup the configration of ap error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
	}
);
/*restore all cfg*/
$app->post(
	'/restorecfg/:filename',
	function($filename) use($app){
		try {
			if ( !empty( $_FILES ) ) {
				$tempPath = $_FILES[ 'file' ][ 'tmp_name' ];
				$uploadPath = "/tmp/".$filename;
				if (file_exists($uploadPath)){
					$remove = 'rm '.$uploadPath;
                	exec($remove,$outr,$err);
				}
				$result = move_uploaded_file( $tempPath, $uploadPath );
				if($result){
					$cmd_check="restore-cfg-check ".$uploadPath;
					$lastres = exec($cmd_check,$out,$ret_check);
					if($ret_check){
						$response = array(
							'success' => false,
							'result'=>'100');
						$log_info ="Configration file is an invalid file or has md5 error ！";
					}else{
						$cmd="cfgrtre ".$uploadPath."  > /dev/null &";
						$lastline = exec($cmd,$out,$ret_err);
						if($ret_err){
							$response = array(
								'success' => false,
								'result'=>'100');
							$log_info ="Configration file is an invalid file or has md5 error ！";
						}else{
							$response = array(
								'success' => true,
								'result' => 'success');
							$log_info ="resotre the configration of ap successfully !";
						}					
					}
				}else{
					$response = array(
						'success' => false,
						'result'=>'101');
					$log_info ="resotre the configration of ap failed : upload file failed !";
				}
    		}else{
    				$response=array(
            			'success'=>false,
            			'result'=>'102');
            		$log_info ="resotre the configration of ap failed : no such file !";
    		}
    		echo json_encode($response);
    		exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'result'=>'103');
        	echo json_encode($error);
			$log_info = "resotre the configration of ap error: ".$e->getMessage();
			exec("logger -t web -p 3 \"".$log_info."\"");
        }
	});
/*update  firmware*/
$app->post(
	'/updatefirm/:filename',
	function($filename) use($app){
		try {
			if ( !empty( $_FILES ) ) {
				$tempPath = $_FILES[ 'file' ][ 'tmp_name' ];
				$uploadPath = '/tmp/'.$filename;
				if (file_exists($uploadPath)){
					$remove = 'rm '.$uploadPath;
					exec($remove,$outr,$err);
				}
				$result = move_uploaded_file( $tempPath, $uploadPath );
				if($result){
					$mem_check_cmd="upgrade-mem-check ";
					exec($mem_check_cmd,$out,$ret_err);
					if(!$ret_err){
						$cmd="osupgrade ".$uploadPath."  > /dev/null &";
						$lastline = exec($cmd,$out,$ret_err);
						if($ret_err){
							$response = array(
								'success' => false,
								'result' => 'failed');
							$log_info ="upload the version of ap failed : osupgrade cmd failed !";
						}else{
							$response = array(
								'success' => true,
								'result' => 'success');
							$log_info ="upload the version of ap successfully !";
						}
					}else{
						$remove = 'rm '.$uploadPath;
						exec($remove,$outr,$err);
						$response=array(
							'success'=>false,
							'result'=>'100'
						);
						$log_info ="upload the version of ap failed : no memory !";
					}
				}else{
					
					$response = array(
						'success' => false,
						'result' => 'upload file failed!'
					);
					$log_info ="upload the version of ap failed !";
				}

			}else{
				$response=array(
					'success'=>false,
					'result'=>'no such file!'
				);
				$log_info ="upload the version of ap failed : no such file !";
			}
			echo json_encode($response);
			exec("logger -t web -p 5 \"".$log_info."\"");
			
        }catch(Exception $e) {
        	$error = array(
        		'success' => false,
        		'msg' => $e->getMessage()
        		);
        	echo json_encode($error);
        	$log_info = "upload the version of ap error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
	});

/*set ap priority*/
$fp2;
$found;

function progress_function($ch,$str){
	global $fp2;
	fwrite($fp2,$str);
	$info=curl_getinfo($ch);
	return strlen($str);
}
function url_check_function($ch,$str){
	global $found;
	$found = true;
	return strlen($str);
}

$app->put(
	'/updatebyurl',
	function() use($app){
		try {
			$result_array = array();
			$mac_cmd="showsysinfo | grep  -E 'MAC'";
			$last_line=exec($mac_cmd,$lines,$ret_err);
			if($ret_err){
				$result_array["mac"]= " ";
			}else{
				$tmp=explode(":", $last_line,2);
				$result_array["mac"]= $tmp[1];
			}
			global $found;
			$found=false;

    		$requestBody=$app->request()->getBody();
    		$requestJson=json_decode($requestBody);
    		$url_str=$requestJson->url;
    		$url_str_array = explode("//",$url_str);
    		$poro = strtoupper(str_replace(":",'',$url_str_array[0]));
    		if(!strcmp($poro,"TFTP")){
    			$ip_info_array = explode("/",$url_str_array[1]);
    			$des_dir="/tmp/".$ip_info_array[1];
				if (file_exists($des_dir)){
					$remove = 'rm '.$des_dir;
					exec($remove,$outr,$err);
				}

				$ch = curl_init($url_str);
				curl_setopt($ch, CURLOPT_HEADER, 0);
    			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    			curl_setopt($ch,CURLOPT_WRITEFUNCTION,"url_check_function"); 
                curl_setopt($ch, CURLOPT_TIMEOUT, 2);
				curl_exec($ch);   
				curl_close($ch);
				if(! $found) {
					$result_array["flag"] = false;
					$result_array["msg"] = "ip_error_or_no_file";
					$response=array(
						'success'=>true,
						'result'=>$result_array
					);
					$log_info ="upload the version of ap by url failed: IP error or file not exist";
				}else{
					global $fp2;
					$fp2=@fopen($des_dir, 'a');
	    			$ch = curl_init();
	    			curl_setopt($ch, CURLOPT_URL, $url_str);
	    			curl_setopt($ch, CURLOPT_HEADER, 0);
	    			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	    			curl_setopt($ch,CURLOPT_WRITEFUNCTION,"progress_function");
	    			$content = curl_exec($ch);
	    			curl_close($ch);
	    			fclose($fp2);
	    			if(!$content){
	    				$result_array["flag"] = false;
	    				$result_array["msg"] = "tftp_cmd_failed";
						$response=array(
							'success'=>true,
							'result'=>$result_array
						);
						$log_info ="upload the version of ap by url failed: tftp cmd failed !";
	    			}else{
	    				$mem_check_cmd="upgrade-mem-check ";
						exec($mem_check_cmd,$out,$ret_err);
						if($ret_err){
							$remove = 'rm /tmp/'.$ip_info_array[1];
							exec($remove,$outr,$err);
							$result_array["flag"] = false;
							$result_array["msg"] = "ap_log_error_3";
							$response=array(
								'success'=>true,
								'result'=>$result_array
							);
							$log_info ="upload the version of ap failed : no memory !";
							echo json_encode($response);
							exec("logger -t web -p 5 \"".$log_info."\"");
						}else{
							$osupgrade="osupgrade /tmp/".$ip_info_array[1].'  > /dev/null &';
							exec($osupgrade,$outr,$err);
							if($err){
								$result_array["flag"] = false;
								$result_array["msg"] = "Failed_to_upgrade";
								$response=array(
									'success'=>true,
									'result'=>$result_array
								);
								$log_info ="upload the version of ap by url failed: osupgrade cmd failed !";
							}else{
								$result_array["flag"] = true;
								$result_array["msg"] = "osupgrade_success";
								$response=array(
									'success'=>true,
									'result'=>$result_array
								);
								$log_info ="upload the version of ap by url successfuly !";
							}
						}
						
					}
				}
    			//$cmd="curl -o /tmp/".$ip_info_array[1]."  ".$url_str;
    		}else if(!strcmp($poro,"FTP")){
    			$first_pos=strpos($url_str_array[1], "/");
    			$ip_port_str=substr($url_str_array[1],0,$first_pos);
    			$end_pos=strrpos($url_str_array[1], "/");
    			$file_user_pass_str=substr($url_str_array[1],$end_pos+1);
    			$file_user_array = explode(":",$file_user_pass_str);
    			$file_name=$file_user_array[0];
    			$username=$file_user_array[1];
    			$passwd=$file_user_array[2];
    			if($first_pos == $end_pos){
    				$filepath="/".$file_name;
    			}else{
    				$filepath_inter=substr($url_str_array[1],$first_pos+1,$end_pos-$first_pos);
    				$filepath="/".$filepath_inter."/".$file_name;
    			}
    			$local_path="/tmp/".$file_name;
    			$port_pos=strrpos($ip_port_str, ":");
    			if(!$port_pos){
    				$conn_id = ftp_connect($ip_port_str);
    			}else{
    				$ftp_server_array=explode(":",$ip_port_str);
    				$conn_id = ftp_connect($ftp_server_array[0], $ftp_server_array[1]);
    			}
    			$login_result = ftp_login($conn_id, $username, $passwd);
    			if($conn_id&&$login_result){
    				$get_result = ftp_get($conn_id, $local_path, $filepath, FTP_BINARY);
    				if($get_result) {
    					$mem_check_cmd="upgrade-mem-check ";
						exec($mem_check_cmd,$out,$ret_err);
						if($ret_err){
							$remove = 'rm /tmp/'.$ip_info_array[1];
							exec($remove,$outr,$err);
							$result_array["flag"] = false;
							$result_array["msg"] = "ap_log_error_3";
							$response=array(
								'success'=>true,
								'result'=>$result_array
							);
							$log_info ="upload the version of ap failed : no memory !";
							echo json_encode($response);
							exec("logger -t web -p 5 \"".$log_info."\"");
						}else{
	    					$osupgrade="osupgrade ".$local_path.'  > /dev/null &';
	    					exec($osupgrade,$outr,$err);
							$result_array["flag"] = true;
							$result_array["msg"] = "osupgrade_success";
	    					$response=array(
	    						'success'=>true,
	    						'result'=>$result_array
	    					);
	    					$log_info ="upload the version of ap by url successfully !";
	    				}
    				} else {
						$result_array["flag"] = false;
						$result_array["msg"] = "Failed_to_get_file_from_ftp_server";
    					$response=array(
    						'success'=>true,
    						'result'=>$result_array
    					);
    					$log_info ="upload the version of ap by url failed: failed to get file from ftp server !";
    				}
    			}else{
    				$result_array["flag"] = false;
                    $result_array["msg"] = "Failed_to_connect_or_failed_to_login";
    				$response=array(
    					'success'=>true,
    					'result'=>$result_array
    				);
    				$log_info ="upload the version of ap by url failed: failed to connect or failed to login !";
    			}
                ftp_close($conn_id);
    		}else{
    			$result_array["flag"] = false;
                $result_array["msg"] = "Input_parameter_is_incorrect";
    			$response=array(
    				'success'=>true,
    				'result'=>$result_array
    			);
    			$log_info ="upload the version of ap by url failed: Input parameter is incorrect !";
    		}
    		echo json_encode($response);
			exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
        	$result_array["flag"] = false;
            $result_array["msg"] = "upload_the_version_of_ap_by_url_error";
        	$error = array(
        		'success' => true,
        		'result' => $result_array );
        	echo json_encode($error);
        	$log_info = "upload the version of ap by url error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
});

/*ledControl ap
*******100:Location
*******101:Restore
*******102:Open
*******103:Off
*/
$app->put(
		'/ledControl',
		function() use($app){
			try {
				$requestBody=$app->request()->getBody();
				$requestJson=json_decode($requestBody);
				$type=$requestJson->type;
				$comand_1="ubus call ledctrl restore;";
				$comand_2="ubus call ledctrl night_mode;";
				$comand_3="ubus call ledctrl blink '{\"leds\":\"RBG\"}'";
				switch($type){
					case 100:
						$command_all = $comand_1.$comand_3;
						break;
					case 101:
					case 102:
						$command_all = $comand_1;
						break;
					case 103:
						$command_all = $comand_1.$comand_2;
						break;
					default:
						$response=array(
							'success'=>false,
							'result'=>"type undefined");
						echo json_encode($response);
						$log_info = "modify the status of led failed: input parameter error !".$type;
						exec("logger -t web -p 5 \"".$log_info."\"");
						return;
				}
				$last_line=exec($command_all,$lines,$ret_err);
				if($ret_err){
					$response=array(
						'success'=>false,
						'result'=>$ret_err
					);
					$log_info = "modify the status of led failed: cmd error !";
				}else{
					$response=array(
						'success'=>true,
						'result'=>$ret_err
					);
					$log_info = "modify the status of led successfully !";
				}
				echo json_encode($response);
				exec("logger -t web -p 7 \"".$command_all."\"");
				exec("logger -t web -p 5 \"".$log_info."\"");
            }catch(Exception $e) {
            	$error = array(
            		'success' => false,
            		'msg' => 'modify the status of led error');
            	echo json_encode($error);
            	$log_info = "modify the status of led: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
            }

});


?>