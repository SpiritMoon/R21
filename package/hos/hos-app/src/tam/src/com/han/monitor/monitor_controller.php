<?php
/**
 * get cpu和mem
 */
$app->get(
    '/monitor/cpuAndMemUsage',
    function (){
		try {
			//5 show cpu utilization
			//6 show mem utilization
			$cmd = 'tech_support_command 5;';

			exec($cmd,$execOut1);
			$cpu = 0;
			if($execOut1 != null){
				$cpu = $execOut1[0];
			}

			$cmd = 'tech_support_command 6;';

			exec($cmd,$execOut2);
			$mem = 0;
			if($execOut2 != null){
				$mem = $execOut2[0];
			}

			$response = array(
						'success' => true,
						'result' => array(
							'cpu' => $cpu,
							'mem' => $mem));	
			echo json_encode($response);

		} catch(Exception $e) {
			$error = array(
						'success' => false,
						'msg' => 'get cpu and mem error');	
			echo json_encode($error);
		}	
    }
);

/**
 * get AP rogueApAndClient
 */
$app->get(
    '/monitor/rogueApAndClient',
    function (){
		try {

			$hapMac = '00:00:00:00:00';
			$list = getRogueApList($hapMac);

			$rogue_ap_num = 0 ;
			$interfering_ap_num = 0;

			if(is_array($list)){
				foreach ($list as $obj) {
					$type = $obj['TYPE'];
					$STA_NUM = $obj['STA_NUM'];
					if($type == 1){//Rogue
						$rogue_ap_num ++;
					}else if($type == 0){//Interfering
						$interfering_ap_num ++;
					}
				}
			}

			$response = array(
						'success' => true,
						'result' => array(
									'rogue_ap_num' => $rogue_ap_num,
									'interfering_ap_num' => $interfering_ap_num)
						);	
			echo json_encode($response);
		} catch(Exception $e) {
			$error = array(
						'success' => false,
						'msg' => 'get rogueApAndClient error');	
			echo json_encode($error);
		}			
    }
);

?>