<?php

/**
*   reload eag_service config
*   return true: reload success
*    return false: reload fail
**/
function reload_eag_config() {
    $cmdStop = "/etc/init.d/eag reload > /dev/null 2>&1 &";
    exec($cmdStop, $output, $return_reload);
	exec("logger -t web -p 7 \"".$cmdStop."\"");
    if((0 === $return_reload)){
        return true;
    }else{
        return false;
    }
}

function get_captive_portal_nums()
{
    $iret=0;
    $cmd = "uci show captive_portal";
    exec($cmd,$out,$return_var);
    if(0 == count($out)){
        return $iret;
    }

    foreach($out as $linenum => $line){
        $header = explode(',',$out[$linenum]);
        $pos1 = explode('@',$header[0]);
        $pos = strpos($pos1[1], '.');
        if(FALSE == $pos ){
            $iret = $iret + 1;
        }
    }

    return $iret;
}


function accord_mac_get_os_nums($usermac){
    $Mac = "\"".$usermac. "\"";
    $cmd = "ubus call user-manage getuser '{\"mac\"".":".$Mac."}'"; 
    exec($cmd,$out,$return_var);

    if(0 == count($out)){
        $return_var = 0;
        $result = "null";
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

            if(3 == $count){
                if((0 == strcmp("devtype", $header[1])) || 
                    (0 == strcmp("ostype", $header[1]))) {

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
    }

    return return_result($return_var, $result);
}

$app->get (
    '/authclientinfo',
    function(){
        $cmd = "eag_cli  show user list";
        exec($cmd,$user,$return_var);
        $temp = 0;

        $result[0][$temp++][key] = "iPhone";
        $result[0][$temp++][key] = "iPad";
        $result[0][$temp++][key] = "Mobile";
        $result[0][$temp++][key] = "PC";
        $result[0][$temp++][key] = "Mac PC";
        $result[0][$temp++][key] = "devUnknown";

        $result[0][$temp++][key] = "IOS";
        $result[0][$temp++][key] = "Android";
        $result[0][$temp++][key] = "BlackBerry";
        $result[0][$temp++][key] = "Mac OS";
        $result[0][$temp++][key] = "Windows ME";
        $result[0][$temp++][key] = "Windows Server";
        $result[0][$temp++][key] = "Windows Vista";
        $result[0][$temp++][key] = "Windows XP";
        $result[0][$temp++][key] = "Windows 7";
        $result[0][$temp++][key] = "Windows 8";
        $result[0][$temp++][key] = "Windows 10";
        $result[0][$temp++][key] = "Linux";
        $result[0][$temp++][key] = "unknown";
        for($i=0;$i<$temp;$i++)
        {
            $result[0][$i][y]=0;
        }
        $temp = 0;

        foreach($user as $linenum => $line){
            if(0 == $linenum){
                continue;
            }
            if(1 == $linenum){
                $key = array("ID","UserName","UserIP",  "UserMAC", "SesstionTime","OutputFlow","InputFlow" , "AuthType");
                continue;
            }else {

                $value = sscanf($line,"%d %s %s %s %d %d %d %s");
                $arrayLen = count($value);
                list($return_var, $osinfo) = accord_mac_get_os($value[3]);
                $devtype = $osinfo[0][devtype];
                $ostype = $osinfo[0][ostype];

                switch ($devtype) {
                    case 'iPhone':
                        $result[0][0][y]++;
                        break;
                    case 'iPad':
                        $result[0][1][y]++;
                        break;
                    case 'Mobile':
                        $result[0][2][y]++;
                        break;
                    case 'PC':
                        $result[0][3][y]++;
                        break;
                    case 'Mac PC':
                        $result[0][4][y]++;
                        break; 
                    default:
                        $result[0][5][y]++;
                        break;
                }

                switch ($ostype) {
                    case 'IOS':
                        $result[0][6][y]++;
                        break;
                    case 'Android':
                        $result[0][7][y]++;
                        break;
                    case 'BlackBerry':
                        $result[0][8][y]++;
                        break;
                    case 'Mac OS':
                        $result[0][9][y]++;
                        break;
                    case 'Windows ME':
                        $result[0][10][y]++;
                        break;
                    case 'Windows Server':
                        $result[0][11][y]++;
                        break;
                    case 'Windows Vista':
                        $result[0][12][y]++;
                        break;
                    case 'Windows XP':
                        $result[0][13][y]++;
                        break;
                    case 'Windows 7':
                        $result[0][14][y]++;
                        break;
                    case 'Windows 8':
                        $result[0][15][y]++;
                        break; 
                    case 'Windows 10':
                        $result[0][16][y]++;
                        break;
                    case 'Linux':
                        $result[0][17][y]++;
                        break;     
                    default:
                        $result[0][18][y]++;
                        break;
                }
            }
        }

        if(0 ==  $return_var) {
                $response = array(
                    'success' => true,
                    'result' => $result);
        }else {
                $response = array(
                    'success' => false,
                    'result' => 'get auth client dev fail!');
        }
        echo json_encode($response);
    }
);

?>