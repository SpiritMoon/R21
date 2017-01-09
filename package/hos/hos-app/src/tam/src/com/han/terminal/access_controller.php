<?php

/**
*   black list
**/
$app->get(
    '/getblacklist',
    function (){
        $mac_nums = 0;
        $result = array();
        $cmd = " config_wlan show_wlan_list_op_global listname maclist";
        exec($cmd,$maclist,$return_var);
        if(0 === count($maclist)){
            $response = array(
                    'success' => true,
                    'result' => $result);
            echo json_encode($response);
            return 0;
        }

        $row = explode(" ", $maclist[0]);
        $len = count($row);
        for($i = 0; $i < $len; $i++){
            $result[$mac_nums++][MAC] = $row[$i];
        }

        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => $result);
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'whitelist list false!');
        }
        echo json_encode($response);
    }
); 

$app->put(
    '/addBlacklist',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
            $maclist_begin = $requestParas->Begin_MAC;
            $maclist_end = $requestParas->End_MAC; 
            if("" == $maclist_begin){
                    $response = array(
                        'success' => true,
                        'result' => 'mac add is null');
                echo json_encode($response);
                return ;
            }

            $cmd = "config_wlan edit_wlan_global macfilter deny noflush";
            exec($cmd,$maclist);
            
            if("" == $maclist_end){
                $cmd = "config_wlan add_wlan_list_global listname maclist listval ".$maclist_begin;
            }else {
                $cmd = "config_wlan add_wlan_list_global listname maclist listval ".$maclist_begin."-".$maclist_end;
            }
            exec($cmd,$maclist,$return_var);

            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => 'add blacklist success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'add black MAC list success!';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'add MAClist error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->delete(
    '/delBlacklist/:usermac',
    function ($usermac){
         try {
            $cmd = "config_wlan del_wlan_list_global listname maclist listval ".$usermac;
            exec($cmd,$out,$return_var);

            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => 'delete black mac success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'delete black mac success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'delete black mac error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }       
    }
);

/*not use*/
$app->delete(
    '/delblacklistall',
    function ($usermac){
         try {
            $cmd = " config_wlan del_wlan_list_op_global listname maclist";
            exec($cmd,$out,$return_var);

            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => 'delete all black mac success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'delete all black mac success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'delete all black mac error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }       
    }
);

/**
*   white list
**/
$app->get(
    '/getwhitelist',
    function (){
        $mac_nums = 0;
        $result = array();
        $cmd = "uci get captive_portal.eag.mac_white_rule";
        exec($cmd,$maclist,$return_var);
        if(0 === count($maclist)){
            $response = array(
                    'success' => true,
                    'result' => $result);
            echo json_encode($response);
            return 0;
        }

        $row = explode(" ", $maclist[0]);
        $len = count($row);
        for($i = 0; $i < $len; $i++){
            $result[$mac_nums++][MAC] = $row[$i];
        }

        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => $result);
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'whitelist list false!');
        }
        echo json_encode($response);
    }
); 

$app->put(
    '/addwhitelist',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
            $maclist_begin = $requestParas->Begin_MAC;
            $maclist_end = $requestParas->End_MAC; 
            if("" == $maclist_begin){
                    $response = array(
                        'success' => true,
                        'result' => 'mac add is null');
                echo json_encode($response);
                return ;
            }

            if("" == $maclist_end){
                $cmd = "eag_uci add_mac_white_rule ".$maclist_begin;
            }else {
                $cmd = "eag_uci add_mac_white_rule ".$maclist_begin."-".$maclist_end;
            }
            exec($cmd,$maclist,$return_var);
            $return_load = reload_eag_config();

            if((0 === $return_var) && ($return_load)){
                $response = array(
                        'success' => true,
                        'result' => 'add MAClist success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'add white MAC list success!';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'add MAClist error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->delete(
    '/delwhitelist/:usermac',
    function ($usermac){
         try {
            $cmd = "eag_uci  del_mac_white_rule ".$usermac;
            exec($cmd,$out,$return_var);

            $return_load = reload_eag_config();

            if((0 === $return_var) && ($return_load)){
                $response = array(
                        'success' => true,
                        'result' => 'delete mac success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'delete mac success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'delete mac error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }       
    }
);

/**
*   wall guardian
**/
$app->get(
    '/getwalllist',
    function (){
        $whitelist_nums = 0;
        $result = array();
        $cmd  = "uci get captive_portal.eag.white_list";
        exec($cmd,$walllist,$return_var);
        if(0 === count($walllist)){
            $response = array(
                    'success' => true,
                    'result' => $result);
            echo json_encode($response);
            return 0;
        }

        $row = explode(" ", $walllist[0]);
        $len = count($row);
        for($i = 0; $i < $len; $i++){
            $result[$whitelist_nums][Domain] = $row[$i];
            $whitelist_nums = $whitelist_nums + 1;
        }

        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => $result);
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'walllist list false!');
        }
        echo json_encode($response);
    }
); 

$app->put(
    '/addwalllist',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
            $white_begin = $requestParas->Begin_IP;
            $white_end = $requestParas->End_IP;

            if(0 == strlen($white_end)){
                $whitelist = $white_begin;
            }else{
                $whitelist = $white_begin."-".$white_end;
            }

            $cmd = "eag_uci add_whitelist ".$whitelist;
            exec($cmd, $out,$return_var);

            $return_load = reload_eag_config();
            if((0 === $return_var) && ($return_load)){
                $response = array(
                        'success' => true,
                        'result' => 'add whitelist success!');
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'add whitelist fail!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = $response->result;
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'add whitelist:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->delete(
    '/delwalllist/:domain',
    function ($domain){
        try {
            $cmd = "eag_uci del_whitelist " .$domain;
            exec($cmd,$whitelist,$return_var);

            $return_load = reload_eag_config();
            if((0 === $return_var) && ($return_load)){
                $response = array(
                        'success' => true,
                        'result' => 'delete whitelist success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'delete whitelist success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'delete whitelist error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
);

?>
