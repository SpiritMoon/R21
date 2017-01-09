<?php

/**
*get AP's'arp-proxy 
**/
$app->get(
    '/network/arpProxy/confParams',
    function () {	
		try {
			$cmd = 'cluster-cfg get arp-proxy.default.proxy_switch;';
			exec($cmd,$execOut);

			$response = array(
					'success' => true,
					'result' =>array('proxySwitch' => $execOut[0] ==1?true:false)
					);
			echo json_encode($response);
		} catch(Exception $e) {
			$error = array(
					'success' => false,
					'msg'=>'uci get arp-proxy  error!');
			echo json_encode($error);
		}		
    }
);

/**
*update AP'sarp-proxy 
**/
$app->put(
    '/network/arpProxy/confParams',
    function () use ($app){
		try {
			$requestBody = $app->request()->getBody();		
			$obj = json_decode($requestBody);
			$proxy_switch_value = $obj->proxySwitch;
			
			if(!is_int($proxy_switch_value)){
				$error = array(
						'success' => false,
						'msg'=>'Parameters must be numeric!');
				echo json_encode($error);					
				return;
			}
			
			$cmd = 'cluster-cfg set arp-proxy.default.proxy_switch='.$proxy_switch_value.';';
			exec($cmd,$execOut);

			//reload
			$reload = '/etc/init.d/arp-proxy reload > /dev/null &';
			exec($reload);		
				
			$response = array(
					'success' => true,
					'msg'=>'');
			echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
			$log_info = 'Modify arpProxy switch to '.$proxy_switch_value.' success';
			exec("logger -t web -p 5 \"".$log_info."\"");	

		} catch(Exception $e) {
			$error = array(
					'success' => false,
					'msg'=>$e->getMessage());
			echo json_encode($error);

			$log_info = 'Modify arpProxy switch fault:'.$e->getMessage();
			exec("logger -t web -p 3 \"".$log_info."\"");				
		}	

    }
);

?>