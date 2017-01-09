<?php
/* 
 *    return_result 
 *    $var:status; $out:array
 */
function return_result($var, $out) {
    $result[0] = $var;
    $result[1] = $out;

    return $result;
}

/*
 * according user mac get terminal os info
 */
function accord_mac_get_os($usermac){ 

    $result = [];
    $Mac = "\"".$usermac. "\"";
    $cmd = "ubus call user-manage getuser '{\"mac\"".":".$Mac."}'"; 
    exec($cmd,$out,$return_var);

    if(0 == count($out)){
        $return_var = 0;
        return return_result($return_var, $result);
    }

    $nums = 0;
    $count = 0;
    foreach($out as $linenum => $line){   
        if($linenum >= 1){                
            $out[$linenum] = trim($out[$linenum]);   
            if(0 == strcmp($out[$linenum], '{')){
                $nums = $nums + 1;
                continue;
            }

            if(0 == strcmp($out[$linenum], '}')){
                continue;
            }
            if(0 == $nums){
                break ;
            }
            $header = explode('"', $out[$linenum]);
             $count = count($header);
            if(5 == $count){
                $result[0][$header[1]]=$header[3];
            }
            if(3 == $count){
                if(0 == strcmp($header[2], "" )){
                        $result[0][$header[1]]=$header[2];
                }else {
                    $row = explode(" ", $header[2]);
                    $info = explode(",", $row[1] );
                    $result[0][$header[1]]=$info[0];
                }
            }
        }
    }

    return return_result($return_var, $result);
}

/*
 * according user mac get terminal auth info
 */
function accord_mac_get_authinfo($usermac){
    $cmd = "eag_cli show user mac ".$usermac; 
    exec($cmd,$user,$return_var);

    if(0 == count($user)){
        $return_var = 0;
        $result = [];
        return return_result($return_var, $result);
    }

    foreach($user as $linenum => $line){
        if(0 == $linenum){
            $key = array("ID","UserName","UserIP",  "UserMAC", "SessionTime","OutputFlow","InputFlow",
                "AuthType", "ESSID");
            continue;
        }else {
            $value = sscanf($line,"%d %s %s %s %s %d %d %s %s");
            $arrayLen = count($value);
            for($i = 0; $i<$arrayLen; $i++){
                $result[0][$key[$i]]=$value[$i];
            }
        }
    }

    return return_result($return_var, $result);
}

/*
 *$time: the seconds 
 *return true: return float as XXdays xx(hours):xx(minutes):xx(seconds)
 *       false: return flase
 */
function Sec2Time($time){

    if(is_numeric($time)){
        $value = array(
          "years" => 0, "days" => 0, "hours" => 0,
          "minutes" => 0, "seconds" => 0,
        );

        if($time >= 86400){
           $value["days"] = floor($time/86400);
           $time = ($time%86400);
        }
        if($time >= 3600){
          $value["hours"] = floor($time/3600);
          $time = ($time%3600);
        }
        if($time >= 60){
          $value["minutes"] = floor($time/60);
          $time = ($time%60);
        }
        $value["seconds"] = floor($time);

        $t=$value[days]."days ".$value["hours"]."h ".$value["minutes"]."m ".$value["seconds"]."s";
        return $t;
    }else{
        return (bool) FALSE;
    }
 }

/*
 *$flow: the flow 
 *return true: return float xx(MB) or xx(KB) or xx(Byte)
 *       false: return flase
 */
function flow_format_conversion($flow){
    if($flow < 0){
        return (bool) FALSE;
    }

    if($flow >= 1024*1024){
       $value = floor($flow/1024/1024);

       return $value."MB";
    }
    if($flow >= 1024){
      $value = floor($flow/1024);
       return $value."kB";
    }

    $value = floor($flow);
    return $value."Byte";
 }

function get_sta_os(){ 

    $cmd= "ubus call user-manage getuser";
    exec($cmd,$out,$return_var);

    $nums = 0;
    $count = 0;
    foreach($out as $linenum => $line){   
        if($linenum >= 2){                
        $out[$linenum] = trim($out[$linenum]);  
            if(0 == strcmp($out[$linenum], '{')){
                $nums = $nums + 1;
                continue;
            }
                                                 
            if(0 == strcmp($out[$linenum], '}')){
                continue;
            }
            if(0 == $nums){
                break ;
            }
            $header = explode('"', $out[$linenum]);
             $count = count($header);
            if(5 == $count){
                $result[$nums-1][$header[1]]=$header[3];
            }
            if(3 == $count){
                if(0 == strcmp($header[2], "" )){
                        $result[$nums-1][$header[1]]=$header[2];
                }else {
                    $row = explode(" ", $header[2]);
                    $info = explode(",", $row[1] );
                    $result[$nums-1][$header[1]]=$info[0];
                }
            }
        }
    }
    return $result;
}

function get_auth_sta(){
    $cmd = "eag_cli  show user list";
    exec($cmd,$user,$return_var);
    if(0 != $return_var){
        $result = "null";
        return return_result($return_var, $result);
    }
	$sta_nums=0;
    foreach($user as $linenum => $line){
        if(0 == strcmp($linenum, "0")){
            continue;
        }

        if(0 == strcmp($linenum, "1")){
            //$key = sscanf($line,"%s %s %s %s %s");
            $key = array("ID","UserName","UserIP",  "UserMAC", "SessionTime","OutputFlow","InputFlow",
                    "AuthType", "ESSID");
            continue;
        }else {
            $value = sscanf($line,"%d %s %s %s %s %d %d %s %s");
            $arrayLen = count($value);
            for($i = 0; $i<$arrayLen; $i++){
                $result[$sta_nums][$key[$i]]=$value[$i];
            }
            $sta_nums = $sta_nums + 1;
        }
    }

    return $result;
}

function get_total_sta_list(){
	//log for web
	exec("web-login-check");

    $result = [];
    $stainfo = array(
                'Name' => "",
                'IP' => "",
                'UserMAC' => "",
                'WLAN' =>"",
                'AP' => "",
                'APName' => "",
                'APInfo' => "",
                'Auth' => "",
                'OnlineTime' => "",
                'SessionTime' => "",
                'RSSI' => 0,
                'MODE' => "NULL",
                'RXRATE' => "",
                'TXRATE' => "",
                'UPRATE' => "",
                'DOWNRATE' => "",
                'InputFlow' => "",
                'OutputFlow' => "",
                'InputFlow_byte' => 0,
                'OutputFlow_byte' => 0,
                'TerminalType' => "Unknown",               
                'FingerPrint' => "Unknown", 
                'FREQ' => "");

    $sta_nums = 0;
    $tmp = 0;
    $gethostname = 0; //record get hostname shell
    $apname = "";
    $work_mode = array(
        "AUTO",
        "11A",
        "11B",
        "11G",
        "FH",
        "TURBO_A",
        "TURBO_G",
        "11NA_HT20",
        "11NG_HT20",
        "11NA_HT40PLUS",
        "11NA_HT40MINUS",
        "11NG_HT40PLUS",
        "11NG_HT40MINUS",
        "11NG_HT40",
        "11NA_HT40",
        "11AC_VHT20",
        "11AC_VHT40PLUS",
        "11AC_VHT40MINUS",
        "11AC_VHT40",
        "11AC_VHT80");
    /*cmd get all relate terminal*/
    $staos = get_sta_os();
    $authinfo = get_auth_sta();

    $cmd= "/usr/sbin/sta_list";
    exec($cmd,$out,$return_var);

    if(0 == count($out)) {
        //$result[$sta_nums].push($stainfo);
        $response = array(
            'success' => false,
            'result' => $result);
        echo json_encode($response);
        return ;
    }

    $key = array("UserMAC","IP","OnlineTime","RX","TX","FREQ","Auth");
    /*Parse sta list*/
    foreach($out as $linenum => $line){
        //get ssid
        if(strstr($out[$linenum], "SSID:")){
            $SSID = explode(':',$out[$linenum]);
            $wlan = $SSID[1];
            continue;
        }

        //Filter out the current line
        if(0 == strcmp($out[$linenum], "STA_MAC              IP                    OnlineTime       RX     TX    FREQ    AUTH")){
            continue;
        }

        $result[$sta_nums] = $stainfo;

        $value = sscanf($line,"%s %s %d %d %d %s %s");
        $arrayLen = count($value);
        for($i = 0; $i<$arrayLen; $i++){
            if(0 == strcmp($key[$i], "OnlineTime")){
                $iret = Sec2Time($value[$i]);
                if(FALSE != $iret){
                    $result[$sta_nums][$key[$i]] = $iret;
                }
            }else{
                $result[$sta_nums][$key[$i]]=$value[$i];
            }
            if(0 == strcmp($key[$i], "RX")){
                $result[$sta_nums][OutputFlow_byte] = $value[$i];
                $iret = flow_format_conversion($value[$i]);
                if(FALSE != $iret){
                    $result[$sta_nums][OutputFlow] = $iret;
                }
            }

            if(0 == strcmp($key[$i], "TX")){
                $result[$sta_nums][InputFlow_byte] = $value[$i];
                $iret = flow_format_conversion($value[$i]);
                if(FALSE != $iret){
                    $result[$sta_nums][InputFlow] = $iret;
                }
            }
        }
        $result[$sta_nums][WLAN]=$wlan;

        // //get os info
        $staoslen = count($staos);
        if(0 < $staoslen){
            for($i = 0; $i<$staoslen; $i++){
                if(0 == strcmp($result[$sta_nums][UserMAC], $staos[$i][mac])){
                $result[$sta_nums][AP] = $staos[$i][ap];
                if(null != $staos[$i][ap] && 0 == $gethostname){
                    $cmd = "cluster-cfg ".$staos[$i][ap]. " get system.sysinfo.hostname";
                    $apname = exec($cmd, $ap);
                    $gethostname = 1;
                }
                $result[$sta_nums][APName] = $apname;
                if("" == $result[$sta_nums][APName] || null == $result[$sta_nums][APName]){
                    $result[$sta_nums][APInfo] = $result[$sta_nums][AP];
                }else {
                    $result[$sta_nums][APInfo] = $result[$sta_nums][APName];
                }

                $result[$sta_nums][RSSI] = $staos[$i][signal];
                $modenum = (int)($staos[$i][mode]);
                if($modenum >= 0 && $modenum < 21){
                    $result[$sta_nums][MODE] = $work_mode[$modenum];
                }else {
                    $result[$sta_nums][MODE] = "NULL";
                }
                
                $result[$sta_nums][RXRATE] = floor($staos[$i][rx_rate] / 1024);
                $result[$sta_nums][TXRATE] = floor($staos[$i][tx_rate] / 1024);
                $result[$sta_nums][UPRATE] = round($staos[$i][up_rate] / 1024 * 8, 2); 
                $result[$sta_nums][DOWNRATE] = round($staos[$i][down_rate] / 1024 * 8, 2); 

                if("" == $staos[$i][devtype]){
                    $result[$sta_nums][TerminalType] = "Unknown";
                }else {
                    $result[$sta_nums][TerminalType] = $staos[$i][devtype];
                }
                
                if("" == $staos[$i][ostype]){
                    $result[$sta_nums][FingerPrint] = "Unknown";
                }else {
                    $result[$sta_nums][FingerPrint] = $staos[$i][ostype];
                }
                }
            }
        }else{
            $result[$sta_nums][AP] = "";
            $result[$sta_nums][APName] = "";
            $result[$sta_nums][RSSI] = 0;
            $result[$sta_nums][MODE] = "NULL";
            $result[$sta_nums][RXRATE] = 0;
            $result[$sta_nums][TXRATE] = 0;
            $result[$sta_nums][UPRATE] = 0;
            $result[$sta_nums][DOWNRATE] = 0;
            $result[$sta_nums][TerminalType] = "Unknown";
            $result[$sta_nums][FingerPrint] = "Unknown";
        }

        $authinfolen = count($authinfo);
        if(0 < count($authinfo)){
            for($i = 0; $i < $authinfolen; $i++){
                if(0 == strcmp($result[$sta_nums][UserMAC], strtolower($authinfo[$i][UserMAC])) && 
                    0 == strcmp($result[$sta_nums][WLAN], $authinfo[$i][ESSID])){
                    if((0 == strcmp("@MAC",$authinfo[$i][UserName])) || 
                        (0 == strcmp("@accesscode",$authinfo[$i][UserName]))){    
                        $result[$sta_nums][Name] = "";
                    }else{
                        $result[$sta_nums][Name] = $authinfo[$i][UserName];
                    }
                    //$result[$sta_nums][Name] = $authinfo[$i][UserName];
                    $result[$sta_nums][SessionTime] = $authinfo[$i][SessionTime];
                    $result[$sta_nums][Auth] = $authinfo[$i][AuthType];
                }
            }
        }


        // list($return_get, $sta) = accord_mac_get_os($result[$sta_nums][UserMAC]);
        // if(0 < count($sta)){
        //     $result[$sta_nums][AP] = $sta[0][ap];
        //     if(null != $sta[0][ap] && 0 == $gethostname){
        //         $cmd = "cluster-cfg ".$sta[0][ap]. " get system.sysinfo.hostname";
        //         $apname = exec($cmd, $ap);
        //         $gethostname = 1;
        //     }
        //     $result[$sta_nums][APName] = $apname;
        //     if("" == $result[$sta_nums][APName] || null == $result[$sta_nums][APName]){
        //         $result[$sta_nums][APInfo] = $result[$sta_nums][AP];
        //     }else {
        //         $result[$sta_nums][APInfo] = $result[$sta_nums][APName];
        //     }

        //     $result[$sta_nums][RSSI] = $sta[0][signal];
        //     $modenum = (int)($sta[0][mode]);
        //     if($modenum >= 0 && $modenum < 21){
        //         $result[$sta_nums][MODE] = $work_mode[$modenum];
        //     }else {
        //         $result[$sta_nums][MODE] = "NULL";
        //     }
            
        //     $result[$sta_nums][RXRATE] = floor($sta[0][rx_rate] / 1024);
        //     $result[$sta_nums][TXRATE] = floor($sta[0][tx_rate] / 1024);
        //     $result[$sta_nums][UPRATE] = round($sta[0][up_rate] / 1024 * 8, 2); 
        //     $result[$sta_nums][DOWNRATE] = round($sta[0][down_rate] / 1024 * 8, 2); 

        //     if("" == $sta[0][devtype]){
        //         $result[$sta_nums][TerminalType] = "Unknown";
        //     }else {
        //         $result[$sta_nums][TerminalType] = $sta[0][devtype];
        //     }
            
        //     if("" == $sta[0][ostype]){
        //         $result[$sta_nums][FingerPrint] = "Unknown";
        //     }else {
        //         $result[$sta_nums][FingerPrint] = $sta[0][ostype];
        //     }
        // }else{
        //     $result[$sta_nums][AP] = "";
        //     $result[$sta_nums][APName] = "";
        //     $result[$sta_nums][RSSI] = 0;
        //     $result[$sta_nums][MODE] = "NULL";
        //     $result[$sta_nums][RXRATE] = 0;
        //     $result[$sta_nums][TXRATE] = 0;
        //     $result[$sta_nums][UPRATE] = 0;
        //     $result[$sta_nums][DOWNRATE] = 0;
        //     $result[$sta_nums][TerminalType] = "Unknown";
        //     $result[$sta_nums][FingerPrint] = "Unknown";
        // }

        // //get auth info
        // list($return_get, $authinfo) = accord_mac_get_authinfo($result[$sta_nums][UserMAC]);
        // if(0 < count($authinfo) && 0 == strcmp($result[$sta_nums][WLAN], $authinfo[0][ESSID])){
        //     if((0 == strcmp("@MAC",$authinfo[0][UserName])) || 
        //         (0 == strcmp("@accesscode",$authinfo[0][UserName]))){    
        //         $result[$sta_nums][Name] = "";
        //     }else{
        //         $result[$sta_nums][Name] = $authinfo[0][UserName];
        //     }
        //     //$result[$sta_nums][Name] = $authinfo[0][UserName];
        //     $result[$sta_nums][SessionTime] = $authinfo[0][SessionTime];
        //     $result[$sta_nums][Auth] = $authinfo[0][AuthType];

        //     // $iret = flow_format_conversion($authinfo[0][InputFlow]);
        //     // if(FALSE != $iret){
        //     //     $result[$sta_nums][InputFlow] = $iret;
        //     // }
        //     // $iret = flow_format_conversion($authinfo[0][OutputFlow]);
        //     // if(FALSE != $iret){
        //     //     $result[$sta_nums][OutputFlow] = $iret;
        //     // }
        //     // $result[$sta_nums][InputFlow_byte] = $authinfo[0][InputFlow];
        //     // $result[$sta_nums][OutputFlow_byte] = $authinfo[0][OutputFlow];
        // }

        $sta_nums = $sta_nums + 1;
    }

    if(0 ==  $return_get) {
        $response = array(
            'success' => true,                
            'result' => $result);
    }else {
        $response = array(
            'success' => false,
            'result' => 'get sta list fail!');
    }
    echo json_encode($response);
}

$app->get(
    '/totalclientlist',
    function () {
        get_total_sta_list();
    }
); 

$app->put(
    '/kickuser',
    function () use ($app){
    try {
        $requestBody = $app->request()->getBody();
        $requestParas = json_decode($requestBody);
        $ssid = $requestParas->WLAN;
        $usermac = $requestParas->UserMAC;
        $userauth = $requestParas->Auth;
        $userip = $requestParas->IP;
        $cmd= "config_wlan kickmac ssid ".$ssid." mac ".$usermac;
        exec($cmd,$out,$return_var);
        if($userauth =="PORTAL"){
            $kickcmd = "eag_cli kick user ip ".$userip;
            exec($kickcmd);
        }


        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => 'kick user success!');
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'kick user fail!');
        }
        
        echo json_encode($response);  
        $log_info = "kick user mac:".$usermac.",ssid:".$ssid.",".$response->result;
		exec("logger -t web -p 7 \"".$cmd."\"");
        exec("logger -t web -p 5 \"".$log_info."\"");  
    }catch(Exception $e) {
        $error = array(
                'success' => false,
                'msg' => $e->getMessage() );
        echo json_encode($error);
        
        $log_info = 'kick user error:'.$e->getMessage();
        exec("logger -t web -p 3 \"".$log_info."\"");      
    } 
    }
);

?>