<?php


/**
*set one ssidname's DSCP/WMM 802.1P/WMM  switch
**/
$app->put(
    '/wlan/:interface/wmmSwitch',
    function ($interface) use ($app){
		try {
			$ssid = ssidEscape($interface);
			$requestBody = $app->request()->getBody();		
			$obj = json_decode($requestBody);
			$switchType = $obj->switchType;
			$switchValue = $obj->switchValue;

			$cmd ='config_wlan edit_wlan ssid '.$ssid.' '.$switchType.' '.$switchValue.' noflush;';
			exec($cmd);
			
			//reload
			$reload = 'wifi flush '.$ssid.' > /dev/null &';
			exec($reload);

			$response = array(
					'success' => true,
					'msg' =>'Modify wmm switch success!');			
			echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
			$log_info = 'edit wmm switch success';
			exec("logger -t web -p 5 \"".$log_info."\"");	
		} catch(Exception $e) {
			$error = array(
					'success' => false,
					'msg' =>$e->getMessage());			
			echo json_encode($error);
			$log_info = 'edit WMM switch error:'.$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);				
		}			
    }
);

/**
*example $str = hanNetwork.dscp_to_bk=1,2 
*return '1,2 '
*/
function analyzeExecOut(&$temp_array, $str){
	$index = strrpos($str,'=');
	$str_key = substr($str,0,$index);  
	$str_vaue = substr($str,$index + 1);  
	$str_vaue = str_replace(" ",",",$str_vaue);
	$temp_array[$str_key] = $str_vaue;
};

/**
*get one ssidname's WMM param
**/
$app->get(
    '/wlan/:interface/wmm/confParams',
    function ($interface) {
		$ssid = ssidEscape($interface);

		//DSCP->WMM down
		$cmd = 'config_wlan get_wmm ssid '.$ssid.';';
		exec($cmd,$execOut);

		$params = array(
				'dscp_enable' => 0,
				'dot1p_enable' => 0,
				'dscp_to_bk' => '2,10',
				'dscp_to_be' => '0,18',
				'dscp_to_vi' => '26,34,40',
				'dscp_to_vo' => '46,48,56',
				'bk_to_dscp' => 10,
				'be_to_dscp' => 0,
				'vi_to_dscp' => 40,
				'vo_to_dscp' => 46,
				'dot1p_to_bk' => '1,2',
				'dot1p_to_be' => '0,3',
				'dot1p_to_vi' => '4,5',
				'dot1p_to_vo' => '6,7',
				'bk_to_dot1p' => 1,
				'be_to_dot1p' => 0,
				'vi_to_dot1p' => 4,
				'vo_to_dot1p' => 6
				);

		try {
			if($execOut != null){ //default
				foreach ($execOut as $str) {
					analyzeExecOut($params, $str);
				}
			}

			//format enable
			$params['dscp_enable'] = ($params['dscp_enable'] ==1)?true:false;
			$params['dot1p_enable'] = ($params['dot1p_enable'] ==1)?true:false;
			$response = array(
					'success' => true,
					'result' =>$params	);		
			echo json_encode($response);

		} catch(Exception $e) {
			$error = array(
					'success' => false,
					'msg' =>'get WMM param error');			
			echo json_encode($error);
		}			
    }
);

/**
*update interface(SSID) 's wmm params
**/
$app->put(
    '/wlan/:interface/wmm/confParams',
    function ($interface) use ($app){
		
		try {
			$ssid = ssidEscape($interface);
			$requestBody = $app->request()->getBody();		
			$obj = json_decode($requestBody);
			
			/**DSCP to WMM dowm**/
			str_replace(",", " ", $ssid);
			$dscp_to_bk_array = str_replace(",", " ", $obj->dscp_to_bk);
			$dscp_to_be_array = str_replace(",", " ", $obj->dscp_to_be);
			$dscp_to_vi_array = str_replace(",", " ", $obj->dscp_to_vi);
			$dscp_to_vo_array = str_replace(",", " ", $obj->dscp_to_vo);
			//dscp_to_bk
			$cmd = 'config_wlan del_wlan_list_op ssid '.$ssid.' listname dscp_to_bk noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dscp_to_bk listval '.$dscp_to_bk_array.' noflush;';

					
			//dscp_to_be
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dscp_to_be noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dscp_to_be listval '.$dscp_to_be_array.' noflush;';

			//dscp_to_vi
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dscp_to_vi noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dscp_to_vi listval '.$dscp_to_vi_array.' noflush;';

			//dscp_to_vo
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dscp_to_vo noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dscp_to_vo listval '.$dscp_to_vo_array.' noflush;';

			/**WMM to DSCP up**/
			$bk_to_dscp = $obj->bk_to_dscp;
			$be_to_dscp = $obj->be_to_dscp;
			$vi_to_dscp = $obj->vi_to_dscp;
			$vo_to_dscp = $obj->vo_to_dscp;
				
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' bk_to_dscp '.$bk_to_dscp.' noflush;';
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' be_to_dscp '.$be_to_dscp.' noflush;';
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' vi_to_dscp '.$vi_to_dscp.' noflush;';
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' vo_to_dscp '.$vo_to_dscp.' noflush;';
					
			//802.1P to WMM Down
			$dot1p_to_bk_array = str_replace(",", " ", $obj->dot1p_to_bk);
			$dot1p_to_be_array = str_replace(",", " ", $obj->dot1p_to_be);
			$dot1p_to_vi_array = str_replace(",", " ", $obj->dot1p_to_vi);
			$dot1p_to_vo_array = str_replace(",", " ", $obj->dot1p_to_vo);
					
			//dscp_to_bk
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dot1p_to_bk noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dot1p_to_bk listval '.$dot1p_to_bk_array.' noflush;';

			//dot1p_to_be
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dot1p_to_be noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dot1p_to_be listval '.$dot1p_to_be_array.' noflush;';

			//dot1p_to_vi
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dot1p_to_vi noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dot1p_to_vi listval '.$dot1p_to_vi_array.' noflush;';

			//dot1p_to_vo
			$cmd = $cmd.'config_wlan del_wlan_list_op ssid '.$ssid.' listname dot1p_to_vo noflush;';	
			$cmd = $cmd.'config_wlan add_wlan_list ssid '.$ssid.' listname dot1p_to_vo listval '.$dot1p_to_vo_array.' noflush;';	
					
			//WMM to DSCP up
			$bk_to_dot1p = $obj->bk_to_dot1p;
			$be_to_dot1p = $obj->be_to_dot1p;
			$vi_to_dot1p = $obj->vi_to_dot1p;
			$vo_to_dot1p = $obj->vo_to_dot1p;
			
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' bk_to_dot1p '.$bk_to_dot1p.' noflush;';
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' be_to_dot1p '.$be_to_dot1p.' noflush;';
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' vi_to_dot1p '.$vi_to_dot1p.' noflush;';
			$cmd = $cmd.'config_wlan edit_wlan ssid '.$ssid.' vo_to_dot1p '.$vo_to_dot1p.' noflush;';	
			exec($cmd);

			//reload
			$reload = 'wifi flush '.$ssid.' > /dev/null &';
			exec($reload);
			
			$response = array(
					'success' => true,
					'msg'=>'');
			echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
			$log_info = 'edit wmm params success';
			exec("logger -t web -p 5 \"".$log_info."\"");	

		} catch(Exception $e) {
			$error = array(
				'success' => false,
				'msg' => $e->getMessage() );
			echo json_encode($error);
			
			$log_info = 'edit wmm params error:'.$e->getMessage();
			exec("logger -t web -p 3 ".$log_info);				
		}	
    }
);

?>