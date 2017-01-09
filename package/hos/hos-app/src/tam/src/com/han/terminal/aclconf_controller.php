<?php

/**
*   reload firewall process
*   return true: reload success
*    return false: reload fail
**/
function reload_firewall_process() {
    $cmdStart = "/etc/init.d/firewall reload";
    exec($cmdStart, $output, $return_reload);

	exec("logger -t web -p 7 \"".$cmdStart."\"");
    if((0 === $return_reload)){
        return true;
    }else{
        return false;
    }
}

function uci_set_firewall($setrule){
    $cmd1 = "cluster-cfg set ".$setrule->rule;

    // if($setrule->src_ip == "" &&
    //     $setrule->src_port == "" &&
    //     $setrule->dest_ip == "" &&
    //     $setrule->dest_port == "" ){

    //     return -1;
    // }

    $name = $setrule->src_ip;
    $cmd = $cmd1.".src_ip=".$name;
    exec($cmd, $out, $return_var);

    $name = $setrule->src_port;
    $cmd = $cmd1.".src_port=".$name;
    exec($cmd, $out, $return_var);

    $name = $setrule->dest_ip;
    $cmd = $cmd1.".dest_ip=".$name;
    exec($cmd, $out, $return_var);
                                                
    $name = $setrule->dest_port;
    $cmd = $cmd1.".dest_port=".$name;
    exec($cmd, $out, $return_var);

    $name = $setrule->proto;
    $name = strtolower($name);
    $cmd = $cmd1.".proto=".$name;
    exec($cmd, $out, $return_var);

    $name = $setrule->target;
    $cmd = $cmd1.".target=".$name;
    exec($cmd, $out, $return_var);

    $return_reload = reload_firewall_process();

    if((0 === $return_var) && ($return_reload)){
        // $response = array(
        //         'success' => true,
        //         'result' => 'set firewall success!');
        return 0;
    }else{
        // $response = array(
        //         'success' => false,
        //         'result' => 'set firewall false!');
        return -1;
    }
}

function config_rule_id($addrulename, $addid){
    $cmd = "uci show firewall";
    exec($cmd,$out,$return_var);

    foreach($out as $linenum => $line){
        $header = explode(',',$out[$linenum]);
        $pos1 = explode('@',$header[0]);
        $pos = strpos($pos1[1], '.');
        if(FALSE == $pos ){
            $var = $var + 1;
            $rule = explode('=',$header[0]);
            $result[$var-1][rule]=$rule[1];

            $row1 = explode('[', $rule[0]);
            $id = explode(']', $row1[1]);
            $result[$var-1][Id]=$id[0];
        }
    }

    $array_len = count($result);
    for($i = 0; $i < $array_len; $i++){
        if($result[$i][Id] > $addid){
            $addid = $result[$i][Id];
        }
    }

    return $addid;
}

function delete_acl_rule($rulename){
    try {
        $cmd1 = "cluster-cfg delete";
        $cmd= $cmd1 ." ".$rulename; 
        exec($cmd, $out, $return_cmd);

        $return_reload = reload_firewall_process();

        if((0 === $return_cmd) && ($return_reload)){
            $response = array(
                    'success' => true,
                    'result' => 'delete acl success!');
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'delete acl fail!');
        }

        echo json_encode($response);

        $log_info = $response->result;
        exec("logger -t web -p 5 ".$log_info);  
    }catch(Exception $e) {
        $error = array(
                'success' => false,
                'msg' => $e->getMessage() );
        echo json_encode($error);
        
        $log_info = 'delete acl:'.$e->getMessage();
        exec("logger -t web -p 3 ".$log_info);      
    }
}

/**
*功能描述
**/

$app->delete(
    '/deleterule/:rule',
    function ($rule){
        delete_acl_rule($rule);
    }
); 

$app->put(
    '/addfirewall',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);

            $cmd= "cluster-cfg add firewall rule";
            exec($cmd,$out,$return_var);

            $id = config_rule_id($rulename, -1);
            $requestParas->rule = "firewall.@rule[".$id."]";

            $cmd1 = "cluster-cfg set "."".$requestParas->rule;
            $cmd = $cmd1.".src=wan";
            exec($cmd, $out, $return_var);

            $cmd1 = "cluster-cfg set "."".$requestParas->rule;
            $cmd = $cmd1.".dest=*";
            exec($cmd, $out, $return_var);

            $return_var = uci_set_firewall($requestParas);
            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => 'add firewall success!');
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'add firewall fail!');
            }
            
            echo json_encode($response);  
            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'add firewall:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        } 
    }
);

$app->put(
    '/modifyfirewall',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);

            $return_var = uci_set_firewall($requestParas);

            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => 'modify firewall success!');
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'modify firewall fail!');
            }
            
            echo json_encode($response);  
            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'modify firewall:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        } 
    }
);

$app->put(
    '/moveACLlist',
    function() use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $acllist = json_decode($requestBody);
            $testa = $acllist[0];
            $testb = $acllist[1];

            $rule = "cluster-cfg set ".$testb->rule;
            $srcip = $rule.".src_ip=".$testa->src_ip.";";
            $srcport = $rule.".src_port=".$testa->src_port.";";
            $destip = $rule.".dest_ip=".$testa->dest_ip.";";
            $destport = $rule.".dest_port=".$testa->dest_port.";";  
            $testa->proto = strtolower($testa->proto);
            $proto = $rule.".proto=".$testa->proto.";";
            $target = $rule.".target=".$testa->target.";";
            $cmda = $srcip.$srcport.$destip.$destport.$proto.$target;

            $rule = "cluster-cfg set ".$testa->rule;
            $srcip = $rule.".src_ip=".$testb->src_ip.";";
            $srcport = $rule.".src_port=".$testb->src_port.";";
            $destip = $rule.".dest_ip=".$testb->dest_ip.";";
            $destport = $rule.".dest_port=".$testb->dest_port.";";
            $testb->proto = strtolower($testb->proto);
            $proto = $rule.".proto=".$testb->proto.";";
            $target = $rule.".target=".$testb->target.";";
            $cmdb = $srcip.$srcport.$destip.$destport.$proto.$target;

            $cmd = $cmda.$cmdb;
            exec($cmd,$out,$return_var);
            $return_reload = reload_firewall_process();
            if((0 === $return_var) && ($return_reload)){
                $response = array(
                        'success' => true,
                        'result' => 'mv acl list success!');
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'mv acl list false!');
            }
            
            echo json_encode($response);

            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'mv acl list:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        }
    }
);

/**
*   set defaults config
**/
$app->put(
    '/setdefaultACL',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
 
            if("accept" == $requestParas){
                $target = ACCEPT;
            }else {
                $target = REJECT;
            }

            $cmd= "cluster-cfg set firewall.@zone[0].forward=".$target;
            exec($cmd, $out, $return_var);

            $return_reload = reload_firewall_process();
            if((0 === $return_var) && ($return_reload)){
                $response = array(
                        'success' => true,
                        'result' => 'set default rule action success!');
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'set default rule action fail!');
            }
            echo json_encode($response);
            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'set default rule action:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        }
    }
);

$app->get(
        '/getdefaultACL',
        function () {
            $cmd= "uci get firewall.@zone[0].forward";
            $iRet = exec($cmd,$out,$return_var);
            sscanf($iRet, "%s", $target);

            if(0 == strcmp($target, "ACCEPT")){
                //$result = true;
                $result = "accept";
            }else {
                //$result = false;
                $result = "reject";
            }

            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => $result);
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'get default rule fail!');
            }
            echo json_encode($response);
        }
);

/**
*   get /etc/config/firewall config
**/

function search_float($header){
    if(0 == strcmp($header, "src") || 
        0 == strcmp($header, "src_ip") || 
        0 == strcmp($header, "src_port") || 
        0 == strcmp($header, "dest") || 
        0 == strcmp($header, "dest_ip") ||
        0 == strcmp($header, "dest_port") || 
        0 == strcmp($header, "proto") ||
        0 == strcmp($header, "target")){
            return 0;
    }
    return -1;
}

$app->get(
    '/aclrule',
    function () {
        $cmd = "uci show firewall";
        exec($cmd,$out,$return_var);
        $var = 0;
        $aclrule = array(
                    'src' => "wan",
                    'rule' => "",
                    'dest' => "",
                    'src_ip' => "Any",
                    'src_ip_flag' => false,
                    'src_port' => "Any",
                    'src_port_flag' => false,
                    'dest_ip' => "Any",
                    'dest_ip_flag' => false,
                    'dest_port' => "Any",
                    'dest_port_flag' => false,
                    'proto' => "",
                    'target' => "");
        $defautlacl =0;
        foreach($out as $linenum => $line){
            $header = explode(',',$out[$linenum]);
            $pos1 = explode('@',$header[0]);
            $pos = strpos($pos1[1], '.');
            if(FALSE == $pos ){
                if($defautlacl < 3){
                    $defautlacl++;
                    continue;
                }

                $var = $var + 1;
                $result[$var - 1] = $aclrule;
                $option = 0;
                $rule = explode('=',$header[0]);
                continue;
            } else {
                $row1 = explode('@',$header[0]);
                $row2 = explode('=',$row1[1]);
                $row3 = explode('.',$row2[0]);
                $iret = search_float($row3[1]);
                if(-1 == $iret){
                    continue; 
                }
                $option = 1;
                if(0 == strcmp("proto", $row3[1])){
                    $result[$var-1][$row3[1]]=strtoupper($row2[1]);
                }else{
                    $result[$var-1][$row3[1]]=$row2[1];
                }
                if(0 == strcmp("src_port", $row3[1])){
                    $result[$var-1][$row3[1]]=(int)($row2[1]);
                }
                if(0 == strcmp("dest_port", $row3[1])){
                    $result[$var-1][$row3[1]]=(int)($row2[1]);
                }
            }

            if(0 == $option){
                $var = $var - 1;
            }else {
                $result[$var-1][rule]=$rule[0];
                //$result[$var-1][Id]=$var;
            }
        }

        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => $result);
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'get acl list fail!');
        }
        echo json_encode($response);
    }
); 

?>
