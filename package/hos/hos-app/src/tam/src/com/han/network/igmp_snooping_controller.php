<?php

/**
*get current AP igmpSnoopingconfig
**/
$app->get(
    '/network/igmpSnooping/confParams',
    function ()use ($app){
		try {
			$cmd = 'cluster-cfg get igmp.igmpsnp.switch;cluster-cfg get igmp.igmpsnp.multounicast;cluster-cfg get igmp.igmpsnp.hostlifeinterval;';
			exec($cmd,$execOut);
			$response = array(
					'success' => true,
					'result' =>array(
						'snoopingSwitch' => $execOut[0] ==1?true:false, 
						'mulitowuicastSwitch' => $execOut[1] ==1?true:false,
						'hostLifeAgeingTime' => $execOut[2])
					);
			echo json_encode($response);
		} catch(Exception $e) {
			$error = array(
					'success' => false,
					'msg' =>$e->getMessage());
			echo json_encode($error);
		}			
    }
);

/**
*update igmpSnoopingconfig
* 
* 1、igmpsnp open
uci set igmp.igmpsnp.switch=1
/etc/init.d/igmpsnp start 
wifi reload 

2、igmpsnp close
uci set igmp.igmpsnp.switch=0
/etc/init.d/igmpsnp stop
wifi reload

3 igmpsnp hostlifeinterval
uci set igmp.igmpsnp.hostlifeinterval=240
/etc/init.d/igmpsnp reload

4、multounicast open/close
uci  igmp.igmpsnp.multounicast = 1|0
wifi reload
**/
$app->put(
    '/network/igmpSnooping/confParams',
    function ()use ($app) {
		try {
			$requestBody = $app->request()->getBody();		
			$obj = json_decode($requestBody);
			$igmpsnp_option = $obj->igmpOption;
			$igmpsnp_value = $obj->igmpOptionValue;
			
			if(!is_int($igmpsnp_value)){//参数不是数字
				$error = array(
						'success' => false,
						'msg'=>'Parameters must be numeric!');
				echo json_encode($error);					
				return;
			}
			
			
			$cmd = 'cluster-cfg set igmp.igmpsnp.'.$igmpsnp_option.'='.$igmpsnp_value.';';
			exec($cmd);

			if($igmpsnp_option == 'switch'){

			   if($igmpsnp_value == 0){//close multounicast
					$close_multounicast = 'cluster-cfg set igmp.igmpsnp.multounicast=0;';
					exec($close_multounicast);
					$stop = '/etc/init.d/igmpsnp stop';
					exec($stop);					
				}else{
					$start = '/etc/init.d/igmpsnp start';
					exec($start);	
				}

				$wifireload = 'athflush igmpsnp > /dev/null &';
				exec($wifireload);	

			}else if($igmpsnp_option == 'multounicast'){

				$wifireload = 'athflush igmpsnp > /dev/null &';
				exec($wifireload);	

			}else if($igmpsnp_option == 'hostlifeinterval'){
				$reload = '/etc/init.d/igmpsnp reload > /dev/null &';
				exec($reload);	
			}

			$response = array(
						'success' => true,
						'msg'=>'');
			echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
			$log_info = 'Modify igmpSnooping params '.$igmpsnp_option.' to '.$igmpsnp_value.' success';
			exec("logger -t web -p 5 \"".$log_info."\"");					
		} catch(Exception $e) {
			$error = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($error);
			$log_info = 'Modify igmpSnooping params error:'.$e->getMessage();
			exec("logger -t web -p 3 \"".$log_info."\"");				
		}			
    }
);

?>