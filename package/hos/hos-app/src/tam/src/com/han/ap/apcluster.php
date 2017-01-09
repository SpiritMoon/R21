<?php
/*get Group and user management*/
$app->get(
		'/getcluster',
		function(){
			try {
				$result_array = array();
    			$com_key=array("cluster_id","cluster_name","cluster_location","cluster_vip","cluster_netmask","Viewer","GuestOperator");
    			$getcluster ="uci get cluster.cluster.";
    			$getsystem1 ="uci get system.";
    			$getsystem2 =".enable;";
    			for ($i=0; $i<count($com_key); $i++)
                {
                	$key = $com_key[$i];
    				if($i < 5){
    					$cmd = $getcluster.$com_key[$i];
    				}else{
    					$cmd = $getsystem1.$com_key[$i].$getsystem2;
    				}
                    $last_line=exec($cmd,$lines,$ret_err);
                    if($ret_err){
    					$result_array[$key] = "";
                    }else{
    					$result_array[$key] = $last_line;
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
            		'msg' => 'get the info of the Group error');
            	echo json_encode($error);
            }
});

$app->put(
		'/reloadclt',
		function() use($app){
			try {
				$reload = '/etc/init.d/cluster restart > /dev/null &';
				$info="Successfully restart Group !";
    			exec($reload);
    			$response=array(
    					'success'=>true,
    					'result'=>"restart_group_suc"
    				);
    			echo json_encode($response);
				exec("logger -t web -p 7 \"".$reload."\"");
				exec("logger -t web -p 5 \"".$info."\"");
			}catch(Exception $e) {
				$error = array(
					'success' => false,
					'msg' => 'restart_group_error');
				echo json_encode($error);
				$log_info = "restart Group error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
			}

});

/*edit  Group   info */
$app->put(
		'/editclusterid',
		function() use($app){
			try {
				$endstr=";";
                $reload = '/etc/init.d/cluster restart > /dev/null &';
    			$requestBody=$app->request()->getBody();
    			$requestJson=json_decode($requestBody);
    			$cltID="cluster-cfg set cluster.cluster.cluster_id=".$requestJson->cluster_id.$endstr;
    			$cmd = $cltID;
    			exec($cmd,$lines,$ret_err);
    			if($ret_err){
    				$response=array(
    					'success'=>false,
    					'msg' => 'modify_groupid_failed'
    				);
    				$log_info ='Failed to modify group ID!';
    			}else{
    				exec($reload);
    				$response=array(
    					'success'=>true,
    					'result'=>'modify_groupid_success'
    				);
    				$log_info ='Group ID changed successfully !';
    			}
    			echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
    			exec("logger -t web -p 5 \"".$log_info."\"");
			}catch(Exception $e) {
				$error = array(
					'success' => false,
					'msg' => 'modify_groupid_error');
				$log_info = "modify group id error: ".$e->getMessage();
				exec("logger -t web -p 3 \"".$log_info."\"");
				echo json_encode($error);
			}

});

/*edit  Group   info */
$app->put(
		'/editclusterinfo',
		function() use($app){
			try {
				$endstr=";";
				$requestBody=$app->request()->getBody();
				$requestJson=json_decode($requestBody);
				$cltName="cluster-cfg set cluster.cluster.cluster_name=".$requestJson->cluster_name.$endstr;
				$cltLoc="cluster-cfg set cluster.cluster.cluster_location=".$requestJson->cluster_location.$endstr;
				//$cltIP="cluster_cli vip ".$requestJson->cluster_vip.$endstr;
				//$cmd = $cltName.$cltLoc.$cltIP;
				$cmd = $cltName.$cltLoc;
				exec($cmd,$lines,$ret_err);
				if($ret_err){
					$response=array(
						'success'=>false,
						'msg' => 'modify_group_info_fail'
					);
					$log_info ='Failed to modify Group Information!';
				}else{
					$response=array(
						'success'=>true,
						'result'=>'modify_group_info_suc'
					);
					$log_info ='Group Information changed successfully !';
				}
				echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
				exec("logger -t web -p 5 \"".$log_info."\"");
            }catch(Exception $e) {
            	$error = array(
            		'success' => false,
            		'msg' => 'modify_group_info_error');
            	$log_info = "modify Group info error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
            	echo json_encode($error);
            }

});

/*edit  Group   info */
$app->put(
		'/editvip',
		function() use($app){
			try {
     			$requestBody=$app->request()->getBody();
     			$requestJson=json_decode($requestBody);
     			$cmd="cluster_cli vip ".$requestJson->cluster_vip."   ".$requestJson->cluster_netmask;
     			exec($cmd,$lines,$ret_err);
     			if($ret_err){
     				$response=array(
     					'success'=>false,
     					'msg' => 'Failed to modify Group vip!'
     				);
     				$log_info ='Failed to modify Group vip!';
     			}else{
     				$response=array(
     					'success'=>true,
     					'result'=>'Group vip changed successfully !'
     				);
     				$log_info ='Group vip changed successfully !';
     			}
     			echo json_encode($response);
				exec("logger -t web -p 7 \"".$cmd."\"");
     			exec("logger -t web -p 5 \"".$log_info."\"");
            }catch(Exception $e) {
            	$error = array(
            		'success' => false,
            		'msg' => 'modify Group vip error');
            	$log_info = "modify Group vip error: ".$e->getMessage();
                exec("logger -t web -p 3 \"".$log_info."\"");
            	echo json_encode($error);
            }

});

/*edit account passwd*/
$app->put(
		'/editpasswd',
		function() use($app){
			try {
				$requestBody = $app->request()->getBody();
				$requestJson = json_decode($requestBody);
				$admin_passwd = $requestJson->admin;
				$view_status =  (int)$requestJson->viewerstatus;
				$view_passwd = $requestJson->view;
				$guest_status =  (int)$requestJson->gueststatus;
				$guest_passwd = $requestJson->guest;

				$conmon_cmd = "cluster-cfg set system.";
				$cmd_adminpwd = $conmon_cmd."Administrator.password=".$admin_passwd;
				$cmd_viewerpwd = $conmon_cmd."Viewer.password=".$view_passwd;
				$cmd_viewerable = $conmon_cmd."Viewer.enable=".$view_status;
				$cmd_guestpwd = $conmon_cmd."GuestOperator.password=".$guest_passwd;
				$cmd_guestable = $conmon_cmd."GuestOperator.enable=".$guest_status;

				$admin_isset_flag=false;
				$view_isset_flag=false;
				$guest_isset_flag=false;
				$flag=true;
				$mess="same";
				$log_info="";


				if(! empty($admin_passwd)){
					$old_admin_passwd_cmd = "uci get system.Administrator.password";
					$old_admin_passwd = exec($old_admin_passwd_cmd);
					if(strcasecmp($old_admin_passwd, $admin_passwd)){
						$admin_isset_flag=true;
					}else{
						$flag = false;
						$mess = $mess."_admin";
						$log_info=$log_info."The new password and the old password of Admin is the same";
					}
				}
				if(($view_status == 1)&&(!empty($view_passwd))){
					$old_view_passwd_cmd = "uci get system.Viewer.password";
					$old_view_passwd = exec($old_view_passwd_cmd);
					if(strcasecmp($old_view_passwd, $view_passwd)){
						$view_isset_flag=true;
					}else{
						$flag = false;
						$mess = $mess."_viewer";
						$log_info=$log_info."The new password and the old password of Viewer is the same";
					}
				}
				if(($guest_status == 1)&&(!empty($guest_passwd))){
					$old_guest_passwd_cmd = "uci get system.GuestOperator.password";
					$old_guest_passwd = exec($old_guest_passwd_cmd);
					if(strcasecmp($old_guest_passwd, $guest_passwd)){
						$guest_isset_flag=true;
					}else{
						$flag = false;
						$mess = $mess."_guest";
						$log_info=$log_info."The new password and the old password of GuestOperator is the same";
					}
				}
				if(!$flag){
					$response=array(
						'success'=>false,
						'msg'=>$mess
					);
					echo json_encode($response);
					exec("logger -t web -p 5 \"".$log_info."\"");
					return;
				}

				exec($cmd_viewerable,$out,$ret_err);
					if($ret_err){
						$flag = false;
						$log_info = $log_info."Failed to enable/disable Viewer !";
					}
				exec($cmd_guestable,$out,$ret_err);
					if($ret_err){
						$flag = false;
						$log_info = $log_info."Failed to enable/disable GuestOperator!";
					}
				if($admin_isset_flag){
					exec($cmd_adminpwd,$out,$ret_err);
					if($ret_err){
						$flag = false;
						$log_info = $log_info."Failed to modify Admin passwd !";
					}
				}
				if($view_isset_flag){
					exec($cmd_viewerpwd,$out,$ret_err);
					if($ret_err){
						$flag = false;
						$log_info = $log_info."Failed to modify Viewer passwd!";
					}
				}
				if($guest_isset_flag){
					exec($cmd_guestpwd,$out,$ret_err);
					if($ret_err){
						$flag = false;
						$log_info = $log_info."Failed to modify GuestOperator passwd!";
					}
				}


				if($flag){
					$response=array(
						'success'=>true,
						'msg'=>"modify_user_info_suc"
					);
					$log_info ="Modify user info successfully !";
				}else{
					$response=array(
						'success'=>false,
						'msg'=>"modify_user_info_fail"
					);
				}
				echo json_encode($response);
				exec("logger -t web -p 5 \"".$log_info."\"");
			}catch(Exception $e) {
				$error = array(
					'success' => false,
					'msg' => 'modify_user_info_error');
				$log_info = "Modify user info error: ".$e->getMessage();
				 exec("logger -t web -p 3 \"".$log_info."\"");
				echo json_encode($error);
			 }
		});
?>