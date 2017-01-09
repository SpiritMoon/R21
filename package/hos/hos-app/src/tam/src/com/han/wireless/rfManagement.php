<?php

/**
*	get rf info
**/
$app->get(
    '/rf',
    function (){
		$country = "US";
		$cmd_country = "cluster-cfg get wireless.wifi0.country";
		$last_line = exec($cmd_country, $lines_country, $return_country);
		//echo "return_country:".$return_country." last_line:".$last_line;
		if((0 === $return_country) && (0 != strcmp($last_line, ""))){
			$country = $last_line;
		}

		$acsSwitch_0 = "OFF";
		$acsSwitch_1 = "OFF";
		$apcSwitch_0 = "OFF";
		$apcSwitch_1 = "OFF";

		$cmd_auto = "uci get wireless.wifi0.channel; uci get wireless.wifi1.channel; uci get wireless.wifi0.txpower; uci get wireless.wifi1.txpower";
		exec($cmd_auto, $lines_auto, $return_auto);
		//var_dump($lines_auto);

		if(0 === $return_auto){
			if(0 == strcmp($lines_auto[0], "auto")){
				$acsSwitch_0 = "ON";
			}

			if(0 == strcmp($lines_auto[1], "auto")){
				$acsSwitch_1 = "ON";
			}

			if(0 == strcmp($lines_auto[2], "auto")){
				$apcSwitch_0 = "ON";
			}

			if(0 == strcmp($lines_auto[3], "auto")){
				$apcSwitch_1 = "ON";
			}
		}

		$cmd_rf = "config_wlan radio_info";
		exec($cmd_rf, $lines_rf, $return_rf);
		//var_dump($lines_rf);

		if(0 === $return_rf){
			foreach ($lines_rf as $linenum => $line) {
				$pos = strpos($line, "=");
				if(FALSE === $pos){
					continue;
				}

				$key = substr($line, 0, $pos);
				$value = substr($line, $pos+1);
				switch($key){
					case "wifi0_Channel":
						sscanf($value, "%d", $channel_0);
						break;
					case "wifi0_Tx-Power":
						sscanf($value, "%d", $power_0);
						break;
					case "wifi1_Channel":
						sscanf($value, "%d", $channel_1);
						break;
					case "wifi1_Tx-Power":
						sscanf($value, "%d", $power_1);
						break;
				}
			}

			$result = array(
						'acsSwitch_2g' => $acsSwitch_0,
						'channel_2g' => $channel_0,
						'acsSwitch_5g' => $acsSwitch_1,
                        'channel_5g' => $channel_1,
                        'apcSwitch_2g' => $apcSwitch_0,
                        'power_2g' => $power_0,
                        'apcSwitch_5g' => $apcSwitch_1,
                        'power_5g' => $power_1,
						'country' => $country);

			$response = array(
						'success' => true,
						'result' => $result);
		}else{
			$response = array(
						'success' => false,
						'result' => 'get rf fail!');
		}

		echo json_encode($response);
	}
);

/**
*	set rf para
**/
$app->put(
    '/rf',
    function () use ($app){
    	try{
    		$requestBody = $app->request()->getBody();
			$requestParas = json_decode($requestBody);
			$channel_2g = $requestParas->channel_2g;
			$channel_5g = $requestParas->channel_5g;
			$power_2g = $requestParas->power_2g;
			$power_5g = $requestParas->power_5g;
			//echo "channel_2g:".$channel_2g." channel_5g:".$channel_5g." power_2g:".$power_2g." power_5g:".$power_5g;

			if(0 != strcmp($channel_2g, "")){
				$cmd = "config_wlan edit_radio device wifi0 channel ".$channel_2g." > /dev/null 2>&1 &";
				//echo "cmd:".$cmd;
				exec($cmd);

				$log_info = "\"".$cmd."\""." result:success";
				exec("logger -t web -p 5 ".$log_info);
			}

			if(0 != strcmp($channel_5g, "")){
				$cmd = "config_wlan edit_radio device wifi1 channel ".$channel_5g." > /dev/null 2>&1 &";
				//echo "cmd:".$cmd;
				exec($cmd);

				$log_info = "\"".$cmd."\""." result:success";
				exec("logger -t web -p 5 ".$log_info);
			}

			if(0 != strcmp($power_2g, "")){
				$cmd = "config_wlan edit_radio device wifi0 txpower ".$power_2g." > /dev/null 2>&1 &";
				//echo "cmd:".$cmd;
				exec($cmd);

				$log_info = "\"".$cmd."\""." result:success";
				exec("logger -t web -p 5 ".$log_info);
			}

			if(0 != strcmp($power_5g, "")){
				$cmd = "config_wlan edit_radio device wifi1 txpower ".$power_5g." > /dev/null 2>&1 &";
				//echo "cmd:".$cmd;
				exec($cmd);

				$log_info = "\"".$cmd."\""." result:success";
				exec("logger -t web -p 5 ".$log_info);
			}

			sleep(5);

			$response = array(
						'success' => true,
						'msg' => 'rf_edit_success');

			echo json_encode($response);
    	}catch(Exception $e){
			$response = array(
						'success' => false,
						'msg' => $e->getMessage());
			echo json_encode($response);

			$log_info = "config rf: ".$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);
		}
	}
);

?>