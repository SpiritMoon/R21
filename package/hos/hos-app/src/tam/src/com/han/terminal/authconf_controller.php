<?php
$app->get(
    '/getauthswitch',
    function (){
        $cmd = "uci get captive_portal.eag.switch";
        $iRet = exec($cmd,$status,$return_var);
        if(0 == count($status)){
            $captiveinfo[CaptiveStatus] = false;
            $return_var = 0;
        } else {
            sscanf($iRet, "%d", $switch);
            if(1 == $switch){
                $captiveinfo[CaptiveStatus]=true;
            }else {
                $captiveinfo[CaptiveStatus]=false;
            }
        }
         
        /*get auth type*/
        $cmd = "uci get captive_portal.eag.auth_mode";
        $iRet = exec($cmd,$Type,$return_var);
        if(0 == count($Type)){
            $captiveinfo[CaptiveType] = 0;
            $return_var = 0;
        } else {
            sscanf($iRet, "%d", $switch);
            $captiveinfo[CaptiveType] = $switch;
        }

        $cmd = "date '+%Y.%m.%d'";
        $nowdate = exec($cmd, $now);
        $captiveinfo[CaptiveTime] = $nowdate;

        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => $captiveinfo);
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'get captive_portal fail!');
        }
        echo json_encode($response);
    }
); 


$app->put(
    '/setportalswitch',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);

            $CaptiveStatus = -1;
            if(flase == $requestParas){
                $CaptiveStatus = 1;
            }else {
                $CaptiveStatus = 0;
            }

            $cmd = "eag_uci switch ".$CaptiveStatus;
            exec($cmd, $output, $return_cmd);

            $return_load = reload_eag_config();

            if((0 === $return_cmd) && ($return_load)){
                $response = array(
                            'success' => true,
                            'result' => 'set switch success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'set auth switch to '.$CaptiveStatus.' success';
            exec("logger -t web -p 5 \"".$log_info."\"");  

        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'set auth swtich error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->put(
    '/setportaltype',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $CaptiveType = json_decode($requestBody);
            $CaptiveType = $CaptiveType - 1;

            $cmd = "eag_uci auth_mode ".$CaptiveType;
            exec($cmd, $output, $return_cmd);

            reload_eag_config();

            if(0 === $return_cmd){
                $response = array(
                            'success' => true,
                            'result' => 'set type success!');
            }
            echo json_encode($response);

			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'set auth type to '.$CaptiveType.' success';
            exec("logger -t web -p 5 \"".$log_info."\"");  

        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'set auth type error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

function get_userinfo($flag){
        $crypto = new Crypto();
        $cmd = "uci get auth_local.accout.userinfo";
        exec($cmd,$user,$return_var);

        if(0 === count($user)){
            // $response = array(
            //         'success' => true,
            //         'result' => $result);
            // echo json_encode($response);
            $result = [];
            return $result;
        }

        if(0 != count($user)){
            $row = explode(" ", $user[0]);
            $len = count($row);
            $guest_nums = 0;
            for($i = 0; $i < $len; $i++){
                $temp = $i % 9;
                // if($user[$i] == "~"){
                //     $user[$i] = "";
                // }
                switch ($temp) {
                    case 0:
                        $result[$guest_nums][UserName] = $row[$i];
                        break;
                    case 1:
                        if(0 == $flag){
                            $userPwd = $row[$i];
                            exec("scvt dec ".$userPwd,$keyoutput, $return_eag);
                            foreach ($keyoutput as $value) {
                                    $userPwd = $value;
                             }
                            $result[$guest_nums][Password] = $crypto->encode($userPwd);
                        }else {
                            $result[$guest_nums][Password] = $row[$i];
                        }
                        break;
                    case 2:
                        if("~" == $row[$i]){
                            $result[$guest_nums][FirstName] = "";
                        }else {
                            $result[$guest_nums][FirstName] = $row[$i];
                        }
                        break;
                    case 3:
                        if("~" == $row[$i]){
                            $result[$guest_nums][LastName] = "";
                        }else {
                            $result[$guest_nums][LastName] = $row[$i];
                        }
                        break; 
                    case 4:
                        if("~" == $row[$i]){
                            $result[$guest_nums][Mail] = "";
                        }else {
                            $result[$guest_nums][Mail] = $row[$i];
                        }
                        break;
                    case 5:
                        if("~" == $row[$i]){
                            $result[$guest_nums][Phone] = "";
                        }else {
                            $result[$guest_nums][Phone] = $row[$i];
                        }
                        break;
                    case 6:
                        if("~" == $row[$i]){
                            $result[$guest_nums][Company] = "";
                        }else {
                            $result[$guest_nums][Company] = $row[$i];
                        }
                        break;
                    case 7:
                        $result[$guest_nums][StartingDate] = $row[$i];
                        break;
                    case 8:
                        $result[$guest_nums][EndingDate] = $row[$i];
                        $guest_nums = $guest_nums + 1;
                        break;
                    default:
                        break;
                }
            }
        }
    return $result;
}

/**
*   get userlist
**/
$app->get(
    '/userlist',
    function (){
        $result = get_userinfo(0);

    	$response = array(
            'success' => true,
            'result' => $result);
        echo json_encode($response);
    }
);

// $app->get(
//     '/userlist11111',
//     function (){
//         $crypto = new Crypto();
//         $reulst = array();
//         $cmd = "uci get auth_local.guest.userinfo";
//         exec($cmd,$guest,$return_guest);
//         $cmd1 = "uci get auth_local.employee.userinfo";
//         exec($cmd1,$employee,$return_employee);

//         if((0 === count($guest)) && (0 === count($employee))){
//             $response = array(
//                     'success' => true,
//                     'result' => $result);
//             echo json_encode($response);
//             return 0;
//         }

//         if(0 != count($guest)){
//             $row = explode(" ", $guest[0]);
//             $len = count($row);
//             $guest_nums = 0;
//             for($i = 0; $i < $len; $i++){
//                 if(0 == ($i % 2)){
//                     $result[$guest_nums][UserName] = $row[$i];
//                 }else {
//                     $result[$guest_nums][Password] = $crypto->encode($row[$i]);
//                     $result[$guest_nums][Group] = "Guest";
//                     $guest_nums = $guest_nums + 1;
//                 }
//             }
//         }

//         if(0 != count($employee)){
//             $row = explode(" ", $employee[0]);
//             $len = count($row);
//             $employ_nums = 0;
//             $employ_nums = $employ_nums + $guest_nums;
//             for($i = 0; $i < $len; $i++) {
//                 if(0 == ($i % 2)){
//                     $result[$employ_nums][UserName] = $row[$i];
//                 }else {
//                     $result[$employ_nums][Password] = $crypto->encode($row[$i]);
//                     $result[$employ_nums][Group] = "Employee";
//                     $employ_nums = $employ_nums + 1;
//                 }
//             }
//         }

//         if(0 === $return_guest || 0 === $return_employee){
//             $response = array(
//                     'success' => true,
//                     'result' => $result);
//         }else{
//             $response = array(
//                     'success' => false,
//                     'result' => 'No find the client!');
//         }
//         echo json_encode($response);
//     }
// );
function operate_user($requestParas, $flag){
    $crypto = new Crypto();
    $UserName     = $requestParas->UserName;
    $Password     = secretEscape($crypto->decode($requestParas->Password));
    //$key = secretEscape($crypto->decode($requestParas->key));
    exec("scvt enc ".$Password,$output, $return_eag);
    foreach ($output as $value) {                                                                                                                                                 
        $Password = $value;                                                                                                                                                       
    }
    if("" == $requestParas->FirstName){
        $FirstName    = "~";
    }else {
        $FirstName    = $requestParas->FirstName;
    }
    if("" == $requestParas->LastName){
        $LastName    = "~";
    }else {
        $LastName    = $requestParas->LastName;
    }
    if("" == $requestParas->Mail){
        $Mail    = "~";
    }else {
        $Mail    = $requestParas->Mail;
    }
    if("" == $requestParas->Phone){
        $Phone    = "~";
    }else {
        $Phone    = $requestParas->Phone;
    }
    if("" == $requestParas->Company){
        $Company    = "~";
    }else {
        $Company    = $requestParas->Company;
    }

    $StartingDate = $requestParas->StartingDate;
    $EndingDate   = $requestParas->EndingDate;

    $userinfo = $UserName." ".$Password." ".$FirstName." ".$LastName." ".$Mail." ".$Phone." ".$Company." ".$StartingDate." ".$EndingDate;

    // var_dump($userinfo);
    if(0 == $flag){
        $cmd = "cluster-cfg del_list auth_local.accout.userinfo=\"".$userinfo."\"";
        exec($cmd,$out,$return_var);

        $adddb = "userm_cli -d ".$UserName;
        exec($adddb,$out);
		
		exec("logger -t web -p 7 \"".$cmd."\"");
		exec("logger -t web -p 7 \"".$adddb."\"");
        $log_info = 'delete account '.$UserName.' success';
        exec("logger -t web -p 5 \"".$log_info."\"");  
    }else {
        $cmd = "cluster-cfg add_list auth_local.accout.userinfo=\"".$userinfo."\"";
        exec($cmd,$out,$return_var);

        $userdb = $UserName." ".$Password." ".$StartingDate." ".$EndingDate;
        $adddb = "userm_cli -a ".$userdb;
        exec($adddb,$out);
		
		exec("logger -t web -p 7 \"".$cmd."\"");
		exec("logger -t web -p 7 \"".$adddb."\"");
        $log_info = 'add account '.$UserName.' success';
        exec("logger -t web -p 5 \"".$log_info."\"");  
    }
}
$app->put(
    '/modifyuser',
    function () use ($app){
        try {
            $crypto = new Crypto();
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
            operate_user($requestParas[0], 0);
            operate_user($requestParas[1], 1);

            $response = array(
                        'success' => true,
                        'result' => 'modify user success!');
            echo json_encode($response);
            $log_info = 'modify user success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'modify user error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->put(
    '/adduser',
    function () use ($app){
        try {
            
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
            operate_user($requestParas, 1);
            // $UserName     = $requestParas->UserName;
            // $Password     = $requestParas->Password;
            // $Password     = $crypto->decode($Password);
            // if("" == $requestParas->FirstName){
            //     $FirstName    = "~";
            // }else {
            //     $FirstName    = $requestParas->FirstName;
            // }
            // if("" == $requestParas->LastName){
            //     $LastName    = "~";
            // }else {
            //     $LastName    = $requestParas->LastName;
            // }
            // if("" == $requestParas->Mail){
            //     $Mail    = "~";
            // }else {
            //     $Mail    = $requestParas->Mail;
            // }
            // if("" == $requestParas->Phone){
            //     $Phone    = "~";
            // }else {
            //     $Phone    = $requestParas->Phone;
            // }
            // if("" == $requestParas->Company){
            //     $Company    = "~";
            // }else {
            //     $Company    = $requestParas->Company;
            // }
            // $StartingDate = $requestParas->StartingDate;
            // $EndingDate   = $requestParas->EndingDate;

            // // $FirstName     = "test";
            // // $LastName     = "dddd";
            // // $Mail         = "hanlet.com";
            // // $Phone        = "18212211111";
            // // $Company      = "hanet";
            // // $StartingDate = "2015.06.15";
            // // $EndingDate   = "2016.12.25";

            // $userinfo = $UserName." ".$Password." ".$FirstName." ".$LastName." ".$Mail." ".$Phone." ".$Company." ".$StartingDate." ".$EndingDate;

            // $cmd = "cluster-cfg add_list auth_local.accout.userinfo=\"".$userinfo."\"";
            // exec($cmd,$out,$return_var);

            // $userdb = $UserName." ".$Password." ".$StartingDate." ".$EndingDate;
            // $adddb = "userm_cli -a ".$userdb;
            // exec($adddb,$out);

            //if((0 === $return_var)){
                $response = array(
                        'success' => true,
                        'result' => 'add user success!');
            //}
            echo json_encode($response);
            $log_info = 'add user success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'add user error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

// $app->put(
//     '/adduser1111',
//     function () use ($app){
//         try {
//             $crypto = new Crypto();
//             $requestBody = $app->request()->getBody();
//             $requestParas = json_decode($requestBody);
//             $UserName = $requestParas->UserName;
//             $Password = $requestParas->Password;
//             $Password = $crypto->decode($Password);
//             $Group = $requestParas->Group;

//             $userinfo = $UserName." ".$Password;

//             if(0 === strcmp($Group, "Guest")){
//                 $cmd = "cluster-cfg add_list auth_local.guest.userinfo=\"".$userinfo."\"";
//             }else {
//                 $cmd = "cluster-cfg add_list auth_local.employee.userinfo=\"".$userinfo."\"";
//             }
//             exec($cmd,$out,$return_var);

//             $adddb = "/etc/init.d/auth_local start";
//             exec($adddb,$out,$return_var);

//             if((0 === $return_var)){
//                 $response = array(
//                         'success' => true,
//                         'result' => 'add user success!');
//             }
//             echo json_encode($response);
//             $log_info = 'add user success';
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'add user:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }
//     }
// ); 

function String_detection($string, $flag){
    $iret = -1;
    switch($flag){
        case 0:
        case 1:
            if (preg_match_all("/^[a-zA-Z0-9_]{4,16}$/", $string, $matches)) { 
                $iret = 0;
            } 
            break;
        case 2:
        case 3:
            if (preg_match_all("/^[a-zA-Z]{0,10}$/", $string, $matches)) { 
                $iret = 0;
            } 
            break;
        case 4:
            if (preg_match_all("/^[A-Za-z0-9@.]{0,30}$/", $string, $matches)) { 
                $iret = 0;
            } 
            break;
        case 5:
            if (preg_match_all("/^[0-9-]{0,20}$/", $string, $matches)) { 
                $iret = 0;
            } 
            break;
        case 6:
            if (preg_match_all("/^[A-Za-z0-9.-_]{0,30}$/", $string, $matches)) { 
                $iret = 0;
            } 
            break;
        case 7:
        case 8:
            if (preg_match_all("/^[0-9.]{1,10}$/", $string, $matches)) { 
                $iret = 0;
            } 
            break;
        default:
            break;
    }

    return $iret;
}

function compare_username($added_user, $add_username)
{
    $iret = -1;
    $len = count($added_user);

    for($i = 0; $i < $len; $i++){
        if(0 == strcmp($added_user[$i][UserName], $add_username)){
            $iret = 0;
            return $iret;
        }
    }
    return $iret;
}
function compare_date($start, $end, $now)
{
    $iret = 0;

    if(0 <= strcmp($start, $end) && 0 <= strcmp($now, $start)){
        $iret = -1;
    }
    return $iret;
}

function import_user($arr){
    $added_user = get_userinfo(1);
    $cmd = "date '+%Y.%m.%d'";
    $nowdate = exec($cmd, $date);
    $success = 0;
    try {
        for ($line= 1;$line< count($arr); $line++){
            $UserName     = $arr[$line][0];
            $Password     = $arr[$line][1];
            if("" == $arr[$line][2]){
                $FirstName = "~"; 
            }else {
                $FirstName = $arr[$line][2];
            }

            if("" == $arr[$line][3]){
                $LastName = "~"; 
            }else {
                $LastName = $arr[$line][3];
            }

            if("" == $arr[$line][4]){
                $Mail = "~"; 
            }else {
                $Mail = $arr[$line][4];
            }

            if("" == $arr[$line][5]){
                $Phone = "~"; 
            }else {
                $Phone = $arr[$line][5];
            }

            if("" == $arr[$line][6]){
                $Company = "~"; 
            }else {
                $Company = $arr[$line][6];
            }

            if(("" == $arr[$line][7]) || ("" == $arr[$line][8])){
                continue;
            }
            $StartingDate = $arr[$line][7];
            $EndingDate   = $arr[$line][8];

            $userRet = String_detection($UserName,0);
            $passwdRet = String_detection($Password,1);
            $firstnameRet = String_detection($FirstName,2);
            $lastnameRet = String_detection($LastName,3);
            $mailRet = String_detection($Mail,4);
            $phoneRet = String_detection($Phone,5);
            $companyRet = String_detection($Company,6);
            $startRet = String_detection($StartingDate,7);
            $endRet = String_detection($EndingDate,8);

            if((0 == $userRet) && (0 == $passwdRet) && 
                (0 == $firstnameRet) && (0 == $lastnameRet) && 
                (0 == $mailRet) && (0 == $phoneRet) && 
                (0 == $companyRet) && (0 == $startRet) && 
                (0 == $endRet) ){
                if(0 != count($added_user)){
                    $iret = compare_username($added_user, $UserName);
                    if(0 == $iret){
                        continue;
                    }
                    $iret = compare_date($startRet, $endRet, $nowdate);
                    if(0 == $iret){
                        continue;
                    }
                }
                $success++;
                //var_dump($success);
                $userinfo = $UserName." ".$Password." ".$FirstName." ".$LastName." ".$Mail." ".$Phone." ".$Company." ".$StartingDate." ".$EndingDate;

                $cmd = "cluster-cfg add_list auth_local.accout.userinfo=\"".$userinfo."\"";
                exec($cmd,$out,$return_var);

                //$userdb = $UserName." ".$Password." ".$StartingDate." ".$EndingDate;
                $adddb = "userm_cli -a ".$userinfo;
                exec($adddb,$outbd);
            }
        }

        $log_info = 'import user success';
        exec("logger -t web -p 5 \"".$log_info."\"");  
    }catch(Exception $e) {
        $log_info = 'import user error:'.$e->getMessage();
        exec("logger -t web -p 3 \"".$log_info."\"");
    }
    return $success;
}

/* csv*/
$app->get(
    '/downloadcsv',
    function (){
        try {
            $FileName="useraccount.csv";
            $filepath="/www/static/assets/res/".$FileName;
            $FileSize=filesize($filepath);
            $file = fopen($filepath, "r");

            header("Content-type: application/octet-stream");

            header("Accept-Ranges: bytes");

            header("Accept-Length: $FileSize");

            header("Content-Disposition: attachment; filename=".$FileName);

            echo fread($file, filesize($filepath));
            fclose($file);
            $log_info = "download csv file successfully !";
            exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
            $error = array(
                'success' => false,
                'msg' => 'download csv file error');
            echo json_encode($error);
            $log_info = "download csv file error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
    }
);

$app->post(
    '/importuser/:filename',
    function($filename) use($app){
        try {
            if ( !empty( $_FILES ) ) {
                $tempPath = $_FILES[ 'file' ][ 'tmp_name' ];
                $uploadFile = '/tmp/user.csv'; 
                if (file_exists($uploadFile)){
                    $remove = 'rm '.$uploadFile;
                    exec($remove, $out, $return_var);
                }

                $result = move_uploaded_file( $tempPath, $uploadFile);
                if($result){
                    $file = fopen('/tmp/user.csv','r'); 
                    while ($data = fgetcsv($file)) {
                        $goods_list[] = $data;
                    }
                    fclose($file);
                    $total = count($goods_list) - 1;
                    $success = import_user($goods_list);
                    // var_dump($total);
                    // var_dump($success);
                    //$result[0][total]= $total;
                    //$uploadinfo = "import total code num:".$total.",success number:".$success;
                    $response = array(
                        'success' => true,
                        'total' => $total,
                        'successTotal'=>$success);
                }else{
                    $response = array(
                        'success' => false,
                        'result' => 'upload file failed!');
                }
            }else{
                $response=array(
                    'success'=>false,
                    'result'=>'no such file!'
                );
            }
            echo json_encode($response);
            $log_info = "upload sucess";
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'upload error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
);

$app->put(
    '/deleteuser',
    function () use ($app){
        try {
            $crypto = new Crypto();
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);
            operate_user($requestParas, 0);
            // $UserName     = $requestParas->UserName;
            // $Password     = $crypto->decode($requestParas->Password);
            // if("" == $requestParas->FirstName){
            //     $FirstName    = "~";
            // }else {
            //     $FirstName    = $requestParas->FirstName;
            // }
            // if("" == $requestParas->LastName){
            //     $LastName    = "~";
            // }else {
            //     $LastName    = $requestParas->LastName;
            // }
            // if("" == $requestParas->Mail){
            //     $Mail    = "~";
            // }else {
            //     $Mail    = $requestParas->Mail;
            // }
            // if("" == $requestParas->Phone){
            //     $Phone    = "~";
            // }else {
            //     $Phone    = $requestParas->Phone;
            // }
            // if("" == $requestParas->Company){
            //     $Company    = "~";
            // }else {
            //     $Company    = $requestParas->Company;
            // }

            // $StartingDate = $requestParas->StartingDate;
            // $EndingDate   = $requestParas->EndingDate;

            // // $FirstName    = "test";
            // // $LastName     = "dddd";
            // // $Mail         = "hanlet.com";
            // // $Phone        = "18212211111";
            // // $Company      = "hanet";
            // // $StartingDate = "2015.06.15";
            // // $EndingDate   = "2016.12.25";

            // $userinfo = $UserName." ".$Password." ".$FirstName." ".$LastName." ".$Mail." ".$Phone." ".$Company." ".$StartingDate." ".$EndingDate;

            // $cmd = "cluster-cfg del_list auth_local.accout.userinfo=\"".$userinfo."\"";
            // exec($cmd,$out,$return_var);

            // $adddb = "userm_cli -d ".$UserName;
            // exec($adddb,$out);

            //if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => 'delete user success!');
            //}
            echo json_encode($response);
            $log_info = 'delete user success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'delete user:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

// $app->put(
//     '/deleteuser',
//     function () use ($app){
//         try {
//             $crypto = new Crypto();
//             $requestBody = $app->request()->getBody();
//             $requestParas = json_decode($requestBody);
//             $UserName = $requestParas->UserName;
//             $Password = $crypto->decode($requestParas->Password);
//             $Group = $requestParas->Group;  
//             $userinfo = $UserName." ".$Password;

//             if(0 === strcmp($Group, "Guest")){
//                 $cmd = "cluster-cfg del_list auth_local.guest.userinfo=\"".$userinfo."\"";
//             }else {
//                 $cmd = "cluster-cfg del_list auth_local.employee.userinfo=\"".$userinfo."\"";
//             }
//             exec($cmd,$out,$return_var);

//             $deldb = "/etc/init.d/auth_local start";
//             exec($deldb,$out,$return_var);

//             if(0 === $return_var){
//                 $response = array(
//                         'success' => true,
//                         'result' => 'delete user success!');
//             }
//             echo json_encode($response);
//             $log_info = 'delete user success';
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'delete user:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }
//     }
// ); 

/**
*    access code
**/
$app->get(
        '/getaccesscode',
        function (){
            $crypto = new Crypto();
            $result = array();
            $code_nums  = 0;
            $cmd = "uci get auth_local.accesscode.code";
            exec($cmd,$accesscode,$return_var);

            if(0 == count($accesscode)){     
                $response = array( 
                    'success' =>true, 
                    'result' => $result);    
                echo json_encode($response);
                return 0; 
            }

            $row = explode(" ", $accesscode[0]);
            $len = count($row);
            for($i = 0; $i < $len; $i++){
                $result[$code_nums++][access_code]= $crypto->encode($row[$i]);
            }

            if(0 === $return_var){
                $response = array(
                        'success' => true,
                        'result' => $result);
            }else{
                $response = array(
                        'success' => false,
                        'result' => 'get accesscode false!');
            }
            echo json_encode($response);
        }
); 

$app->put(
    '/addaccesscode',
    function () use ($app){
        try {
            $crypto = new Crypto();
            $requestBody = $app->request()->getBody();
            $access_code = json_decode($requestBody);
	    $access_code = $crypto->decode($access_code);

            $cmd = "cluster-cfg add_list auth_local.accesscode.code=\"".$access_code."\"";
            exec($cmd,$out,$return_var);
            $adddb = "userm_cli -A ".$access_code;
            exec($adddb,$out);
            // $adddb = "/etc/init.d/auth_local start";
            // exec($adddb,$out,$return_var);

            if((0 === $return_var)){
                $response = array(
                    'success' => true,
                    'result' => 'add accesscode success!');
            }
            echo json_encode($response);
			
			exec("logger -t web -p 7 \"".$cmd."\"");
            $log_info = 'add accesscode success';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'add accesscode error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->get(
    '/downloadcodecsv',
    function (){
        try {
            $FileName="code.csv";
            $filepath="/www/static/assets/res/".$FileName;
            $FileSize=filesize($filepath);
            $file = fopen($filepath, "r");

            header("Content-type: application/octet-stream");

            header("Accept-Ranges: bytes");

            header("Accept-Length: $FileSize");

            header("Content-Disposition: attachment; filename=".$FileName);

            echo fread($file, filesize($filepath));
            fclose($file);
            $log_info = "download csv file successfully !";
            exec("logger -t web -p 5 \"".$log_info."\"");
        }catch(Exception $e) {
            $error = array(
                'success' => false,
                'msg' => 'download csv file error');
            echo json_encode($error);
            $log_info = "download csv file error: ".$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");
        }
    }
);

function access_detection($string){
    $iret = -1;

    if (preg_match_all("/^[a-zA-Z0-9]{4,8}$/", $string, $matches)) { 
        $iret = 0;
        return $iret;
    } 

    return $iret;
}

function compare_code($added_code, $add_username)
{
    $iret = -1;
    $len = count($added_code);

    for($i = 0; $i < $len; $i++){
        if(0 == strcmp($added_code[$i][access_code], $add_username)){
            $iret = 0;
            return $iret;
        }
    }
    return $iret;
}

function get_codeinfo(){
    $result = array();
    $code_nums  = 0;
    $cmd = "uci get auth_local.accesscode.code";
    exec($cmd,$accesscode,$return_var);

    if(0 == count($accesscode)){     
        // $response = array( 
        //     'success' =>true, 
        //     'result' => $result);    
        // echo json_encode($response);
        return 0; 
    }

    $row = explode(" ", $accesscode[0]);
    $len = count($row);
    for($i = 0; $i < $len; $i++){
        $result[$code_nums++][access_code]= $row[$i];
    }
    return $result;
}

function import_access($arr){
    $success = 0;
    $added_code = get_codeinfo();
    try {
        for ($line= 1;$line< count($arr); $line++){
            $access_code = $arr[$line][0];
            $codeRet = access_detection($access_code);

            if(0 == $codeRet){
                if(0 != count($added_code)){
                    $iret = compare_code($added_code, $access_code);
                    if(0 == $iret){
                        continue;
                    }
                }
                $success++;
                $cmd = "cluster-cfg add_list auth_local.accesscode.code=\"".$access_code."\"";
                exec($cmd,$out,$return_var);
                $adddb = "userm_cli -A ".$access_code;
                exec($adddb,$out);
				
				exec("logger -t web -p 7 \"".$cmd."\"");
				$log_info = 'add accesscode success';
				exec("logger -t web -p 5 \"".$log_info."\"");  
            }
        }

        $log_info = 'loadingin code success';
        exec("logger -t web -p 5 ".$log_info);  
    }catch(Exception $e) {
        $log_info = 'import code:'.$e->getMessage();
        exec("logger -t web -p 3 ".$log_info);
    }
    return $success;
}

$app->post(
    '/importcode/:filename',
    function($filename) use($app){
        try {
            if ( !empty( $_FILES ) ) {
                $tempPath = $_FILES[ 'file' ][ 'tmp_name' ];
                $uploadFile = '/tmp/access.csv'; 
                if (file_exists($uploadFile)){
                    $remove = 'rm '.$uploadFile;
                    exec($remove, $out, $return_var);
                }

                $result = move_uploaded_file( $tempPath, $uploadFile);
                if($result){
                    $file = fopen('/tmp/access.csv','r'); 
                    while ($data = fgetcsv($file)) {
                        $goods_list[] = $data;
                    }
                    fclose($file);
                    $success = import_access($goods_list);
                    $total = count($goods_list) - 1;
                    // $uploadinfo = "import total code num:".$total.",success number:".$success;
                    // $response = array(
                    //     'success' => true,
                    //     'result' => $uploadinfo);
                    $response = array(
                        'success' => true,
                        'total' => $total,
                        'successTotal'=>$success);
                }else{
                    $response = array(
                        'success' => false,
                        'result' => 'upload file failed!');
                }
            }else{
                $response=array(
                    'success'=>false,
                    'result'=>'no such file!'
                );
            }
            echo json_encode($response);
            $log_info = $response->result;
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'upload accesscode file error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
);

$app->delete(
    '/deleteaccesscode/:accesscode',
    function ($accesscode){
        try {
            $crypto = new Crypto();
            $accesscode = $crypto->decode($accesscode);
            $cmd = "cluster-cfg del_list auth_local.accesscode.code=\"".$accesscode."\"";
            exec($cmd,$whitelist,$return_var);
            $adddb = "userm_cli -D ".$accesscode;
            exec($adddb,$out);
            // $adddb = "/etc/init.d/auth_local start";
            // exec($adddb,$out,$return_var);

            if((0 === $return_var)){
                $response = array(
                        'success' => true,
                        'result' => 'delete accesscode success!');
            }
            echo json_encode($response);
            $log_info = 'delete accesscode success!';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'delete accesscode error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

/**
*   mac list
**/
// $app->get(
//     '/getmaclist',
//     function (){
//         $mac_nums = 0;
//         $result = array();
//         $cmd = "uci get captive_portal.eag.mac_white_rule";
//         exec($cmd,$maclist,$return_var);
//         if(0 === count($maclist)){
//             $response = array(
//                     'success' => true,
//                     'result' => $result);
//             echo json_encode($response);
//             return 0;
//         }

//         $row = explode(" ", $maclist[0]);
//         $len = count($row);
//         for($i = 0; $i < $len; $i++){
//             $result[$mac_nums++][MAC_Addr_Info] = $row[$i];
//         }

//         if(0 === $return_var){
//             $response = array(
//                     'success' => true,
//                     'result' => $result);
//         }else{
//             $response = array(
//                     'success' => false,
//                     'result' => 'whitelist list false!');
//         }
//         echo json_encode($response);
//     }
// ); 

// $app->put(
//     '/addmaclist',
//     function () use ($app){
//         try {
//             $requestBody = $app->request()->getBody();
//             $requestParas = json_decode($requestBody);
//             $maclist_begin = $requestParas->Begin_MAC;
//             $maclist_end = $requestParas->End_MAC; 
//             if("" == $maclist_begin){
//                     $response = array(
//                         'success' => true,
//                         'result' => 'mac add is null');
//                 echo json_encode($response);
//                 return ;
//             }

//             if("" == $maclist_end){
//                 $cmd = "eag_uci add_mac_white_rule ".$maclist_begin;
//             }else {
//                 $cmd = "eag_uci add_mac_white_rule ".$maclist_begin."-".$maclist_end;
//             }
//             exec($cmd,$maclist,$return_var);
//             $return_load = reload_eag_config();

//             if((0 === $return_var) && ($return_load)){
//                 $response = array(
//                         'success' => true,
//                         'result' => 'add MAClist success!');
//             }
//             echo json_encode($response);

//             $log_info = 'add MAClist success!';
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'add MAClist:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }
//     }
// ); 

// $app->delete(
//     '/deletemaclist/:usermac',
//     function ($usermac){
//          try {
//             $cmd = "eag_uci  del_mac_white_rule ".$usermac;
//             exec($cmd,$out,$return_var);

//             $return_load = reload_eag_config();

//             if((0 === $return_var) && ($return_load)){
//                 $response = array(
//                         'success' => true,
//                         'result' => 'delete mac success!');
//             }
//             echo json_encode($response);

//             $log_info = 'delete mac success';
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'delete mac:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }       
//     }
// );

$app->put(
    '/restoredefault',
    function () use ($app){
        try {
            $defaultpath = "/www/internal_portal/default/";
            $pngpath = "/www/internal_portal/static/img/";
            $txtpath = "/www/internal_portal/";
            $png = "cp ".$defaultpath."*.png ".$pngpath.";";
            $txt = "cp ".$defaultpath."*.txt ".$txtpath;
            $cmd = $png.$txt;
            exec($cmd);

            $response = array(
                    'success' => true,
                    'result' => 'restore defautl portal success!');
            echo json_encode($response);

            $log_info = 'restore defautl portal success!';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'restore default portal error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
);

/**
*   portal page
**/
$app->post(
    '/uploadlogo/:filename',
    function($filename) use($app){
        try {
            if ( !empty( $_FILES ) ) {
                $tempPath = $_FILES[ 'file' ][ 'tmp_name' ];

                if(strstr($filename,"png")||strstr($filename,"PNG")){
                    $uploadFile = '/www/internal_portal/static/img/logo.png';
                    if (file_exists($uploadFile)){
                        $remove = 'rm '.$uploadFile;
                        exec($remove, $out, $return_var);
                    }
                    $uploadFileImg = '/www/internal_portal/static/img/logo.jpg';
                    if(file_exists($uploadFileImg)){
                        $remove = 'rm '.$uploadFileImg;
                        exec($remove, $out, $return_var);
                    }
                    $result = move_uploaded_file( $tempPath, $uploadFile);
                }else{
                    $uploadFile = '/www/internal_portal/static/img/logo.jpg';
                    if(file_exists($uploadFile)){
                        $remove = 'rm '.$uploadFile;
                        exec($remove, $out, $return_var);
                    }
                    $uploadFileImg = '/www/internal_portal/static/img/logo.png';
                    if(file_exists($uploadFileImg)){
                        $remove = 'rm '.$uploadFileImg;
                        exec($remove, $out, $return_var);
                    }
                    $result = move_uploaded_file( $tempPath, $uploadFile);
                }
                if($result){
                    $response = array(
                        'success' => true,
                        'result' => 'uploadlogo success');
                }else{
                $response = array(
                    'success' => false,
                    'result' => 'upload file failed!');
                }
            }else{
                $response=array(
                    'success'=>false,
                    'result'=>'no such file!'
                );
            }
            echo json_encode($response);

            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'uploadlogo:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        }
    }
);

$app->post(
    '/uploadmain/:filename',
    function($filename) use($app){
        try {
            if ( !empty( $_FILES ) ) {
                $tempPath = $_FILES[ 'file' ][ 'tmp_name' ];
                if(strstr($filename,"png")||strstr($filename,"PNG")){
                    $uploadFile = '/www/internal_portal/static/img/bg.png';
                    if (file_exists($uploadFile)){
                        $remove = 'rm '.$uploadFile;
                        exec($remove, $out, $return_var);
                    }
                    $uploadFileImg = '/www/internal_portal/static/img/bg.jpg';
                    if(file_exists($uploadFileImg)){
                        $remove = 'rm '.$uploadFileImg;
                        exec($remove, $out, $return_var);
                    }
                    $result = move_uploaded_file( $tempPath, $uploadFile);
                }else{
                    $uploadFile = '/www/internal_portal/static/img/bg.jpg';
                    echo "this is jpg";
                    if(file_exists($uploadFile)){
                        $remove = 'rm '.$uploadFile;
                        exec($remove, $out, $return_var);
                    }
                    $uploadFileImg = '/www/internal_portal/static/img/bg.png';
                    if(file_exists($uploadFileImg)){
                        $remove = 'rm '.$uploadFileImg;
                        exec($remove, $out, $return_var);
                    }
                    $result = move_uploaded_file( $tempPath, $uploadFile);
                }

                if($result){
                    $response = array(
                        'success' => true,
                        'result' => 'success');
                }else{
                    $response = array(
                        'success' => false,
                        'result' => 'upload file failed!');
                }
            }else{
                $response=array(
                    'success'=>false,
                    'result'=>'no such file!'
                );
            }
            echo json_encode($response);
            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'uploadmain:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        }
    }
);

$app->post(
    '/uploadlicense/:filename',
    function($filename) use($app){
        try {
            if ( !empty( $_FILES ) ) {
                $tempPath = $_FILES[ 'file' ][ 'tmp_name' ];
                $uploadFile = '/www/internal_portal/license.txt'; 
                if (file_exists($uploadFile)){
                    $remove = 'rm '.$uploadFile;
                    exec($remove, $out, $return_var);
                }

                $result = move_uploaded_file( $tempPath, $uploadFile);
                if($result){
                    $response = array(
                        'success' => true,
                        'result' => 'success');
                }else{
                    $response = array(
                        'success' => false,
                        'result' => 'upload file failed!');
                }
            }else{
                $response=array(
                    'success'=>false,
                    'result'=>'no such file!'
                );
            }
            echo json_encode($response);
            $log_info = $response->result;
            exec("logger -t web -p 5 ".$log_info);  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'uploadlicense:'.$e->getMessage();
            exec("logger -t web -p 3 ".$log_info);      
        }
    }
);

// /**
// *   access control
// **/
// function get_access_control(){
//     $rule = "uci get captive_portal.eag.";
//     //access control
//     $cmd = $rule."idletime";
//     $iRet = exec($cmd,$time,$return_var);
//     if(0 === count($time)){
//         $result[Idle_timeout]= 1800;
//         $return_var = 0;
//     }else{
//         sscanf($iRet, "%d", $idletime);
//         $result[Idle_timeout]= $idletime;
//     }

//     if(0 != $return_var){
//         $response = array(
//             'success' => false,
//             'result' => 'get idletime fail!');

//         echo json_encode($response);
//         return ;
//     } 


//     $cmd = $rule."idleflow";
//     $iRet = exec($cmd,$out,$return_var);
//     if(0 === count($out)){
//         $result[Idle_flow]= 10240;
//         $return_var = 0;
//     }else{
//         sscanf($iRet, "%d", $idleflow);
//         $result[Idle_flow]= $idleflow;
//     }

//     if(0 != $return_var){
//         $response = array(
//             'success' => false,
//             'result' => 'get idleflow fail!');

//         echo json_encode($response);
//         return ;
//     } 

//     $cmd = $rule."account_interval";
//     $iRet = exec($cmd,$out,$return_var);
//     if(0 === count($out)){
//         $result[Account_internal]= 900;
//         $return_var = 0;
//     }else{
//         sscanf($iRet, "%d", $interval);
//         $result[Account_internal]= $interval;
//     }

//     if(0 != $return_var){
//         $response = array(
//             'success' => false,
//             'result' => 'get Account_internal fail!');

//         echo json_encode($response);
//         return ;
//     } 

//     if(0 === $return_var){
//         $response = array(
//                 'success' => true,
//                 'result' => $result);
//     }else{
//         $response = array(
//                 'success' => false,
//                 'result' => 'getaccesscontrol false!');
//     }
//     echo json_encode($response);
// }

// $app->get(
//         '/getaccesscontrol',
//         function (){
//             get_access_control();
//         }
// ); 

// $app->put(
//     '/setaccesscontrol',
//     function () use ($app){
//         try {
//             $requestBody = $app->request()->getBody();
//             $requestParas = json_decode($requestBody);

//             $IdleTimeout = $requestParas->Idle_timeout;
//             $IdleFlow = $requestParas->Idle_flow;
//             $AccountInterval = $requestParas->Account_internal;

//             $rule = "cluster-cfg set captive_portal.@captive_portal[0].";
//             $idletime = $rule."idletime=".$IdleTimeout;
//             $idleflow = $rule."idleflow=".$IdleFlow;
//             $interval = $rule."account_interval=".$AccountInterval;
//             $cmd = $idletime.";".$idleflow.";".$interval.";";
//             exec($cmd, $out, $return_var);
     
//             $return_load = reload_eag_config();

//             if((0 === $return_var) && ($return_load)){
//                 $response = array(
//                     'success' => true,
//                     'result' => 'set access control success!');
//             }
//             echo json_encode($response);
//             $log_info = 'set access control success!';
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'set access control:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }
//     }
// ); 

/**
*   white list
**/
// $app->get(
//     '/getwhitelist',
//     function (){
//         $whitelist_nums = 0;
//         $result = array();
//         $cmd  = "uci get captive_portal.eag.white_list";
//         exec($cmd,$whitelist,$return_var);
//         if(0 === count($whitelist)){
//             $response = array(
//                     'success' => true,
//                     'result' => $result);
//             echo json_encode($response);
//             return 0;
//         }

//         $row = explode(" ", $whitelist[0]);
//         $len = count($row);
//         for($i = 0; $i < $len; $i++){
//             $result[$whitelist_nums][Domain] = $row[$i];
//             $whitelist_nums = $whitelist_nums + 1;
//         }

//         if(0 === $return_var){
//             $response = array(
//                     'success' => true,
//                     'result' => $result);
//         }else{
//             $response = array(
//                     'success' => false,
//                     'result' => 'whitelist list false!');
//         }
//         echo json_encode($response);
//     }
// ); 

// $app->put(
//     '/addwhitelist',
//     function () use ($app){
//         try {
//             $requestBody = $app->request()->getBody();
//             $requestParas = json_decode($requestBody);
//             $white_begin = $requestParas->Begin_IP;
//             $white_end = $requestParas->End_IP;

//             if(0 == strlen($white_end)){
//                 $whitelist = $white_begin;
//             }else{
//                 $whitelist = $white_begin."-".$white_end;
//             }

//             $cmd = "eag_uci add_whitelist ".$whitelist;
//             exec($cmd, $out,$return_var);

//             $return_load = reload_eag_config();
//             if((0 === $return_var) && ($return_load)){
//                 $response = array(
//                         'success' => true,
//                         'result' => 'add whitelist success!');
//             }else{
//                 $response = array(
//                         'success' => false,
//                         'result' => 'add whitelist fail!');
//             }
//             echo json_encode($response);

//             $log_info = $response->result;
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'add whitelist:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }
//     }
// ); 

// $app->delete(
//     '/deletewhitelist/:domain',
//     function ($domain){
//         try {
//             $cmd = "eag_uci del_whitelist " .$domain;
//             exec($cmd,$whitelist,$return_var);

//             $return_load = reload_eag_config();
//             if((0 === $return_var) && ($return_load)){
//                 $response = array(
//                         'success' => true,
//                         'result' => 'delete whitelist success!');
//             }
//             echo json_encode($response);

//             $log_info = 'delete whitelist success';
//             exec("logger -t web -p 5 ".$log_info);  
//         }catch(Exception $e) {
//             $error = array(
//                     'success' => false,
//                     'msg' => $e->getMessage() );
//             echo json_encode($error);
            
//             $log_info = 'delete whitelist:'.$e->getMessage();
//             exec("logger -t web -p 3 ".$log_info);      
//         }
//     }
// );


$app->get(
    '/getTftpInfo',
    function (){
        $tftpinfo = array();
        $cmd = "cluster-cfg get tftplog.tftp.turn_on_off";
        $iSwitch = exec($cmd,$out,$return_var);
        if(0 == count($out)){
            $tftpinfo[FTFPStatus] = false;
            $return_var = 0;
        } else {
            if("on" == $iSwitch){
                $tftpinfo[FTFPStatus]=true;
            }else {
                $tftpinfo[FTFPStatus]=false;
            }
        }
        
        $cmd = "cluster-cfg get tftplog.tftp.ip_auto";
        $IP = exec($cmd,$TFTPip,$return_var);
        if(0 == count($TFTPip)){
            $tftpinfo[TFTPIp] = "";
            $return_var = 0;
        } else {
            $tftpinfo[TFTPIp] = $IP;
        }

        $cmd = "cluster-cfg get tftplog.tftp.timer";
        $Cycle = exec($cmd,$TFTPCycle,$return_var);
        if(0 == count($TFTPCycle)){
            $tftpinfo[TFTPCycle] = 0;
            $return_var = 0;
        } else {
            sscanf($Cycle, "%d", $Cycle);
            $tftpinfo[TFTPCycle] = $Cycle;
        }

        if(0 === $return_var){
            $response = array(
                    'success' => true,
                    'result' => $tftpinfo);
        }else{
            $response = array(
                    'success' => false,
                    'result' => 'whitelist list false!');
        }
        echo json_encode($response);
    }
); 


$app->put(
    '/settftpswitch',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);

            $TftpStatus = "off";
            if(flase == $requestParas){
                $TftpStatus = "on";
            }else {
                $TftpStatus = "off";
            }

            $cmd = "cluster-cfg set tftplog.tftp.turn_on_off=".$TftpStatus;
            exec($cmd, $out, $return_var);
			exec("logger -t web -p 7 \"".$cmd."\"");
			
            $cmd = "/etc/init.d/tftp_script start";
            exec($cmd, $upload);
			exec("logger -t web -p 7 \"".$cmd."\"");
			
            if(0 === $return_var){
                $response = array(
                            'success' => true,
                            'result' => 'set tftp server swtich success!');
            }
            echo json_encode($response);

            $log_info = 'set tftp server switch to '.$TftpStatus.' success';
            exec("logger -t web -p 5 \"".$log_info."\"");  

        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'set tftp server swtich error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->put(
    '/savetftpinfo',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);

            $switch = $requestParas->FTFPStatus;
            $ip = $requestParas->TFTPIp;
            $cycle = $requestParas->TFTPCycle;

            
            $cmdip = "cluster-cfg set tftplog.tftp.ip_auto=".$ip.";";
            $cmdcycle = "cluster-cfg set tftplog.tftp.timer=".$cycle;
            $cmd = $cmdip.$cmdcycle;
            exec($cmd, $out, $return_var);
			exec("logger -t web -p 7 \"".$cmd."\"");
			
            $cmd = "/etc/init.d/tftp_script start";
            exec($cmd, $upload);
			exec("logger -t web -p 7 \"".$cmd."\"");
			
            if(0 === $return_var){
                $response = array(
                    'success' => true,
                    'result' => 'set TFTP info success!');
            }
            echo json_encode($response);
            $log_info = 'set TFTP ip:'.$ip.', timer:'.$cycle.' success!';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'set TFTP info error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
); 

$app->put(
    '/uploadtftpinfo',
    function () use ($app){
        try {
            $requestBody = $app->request()->getBody();
            $requestParas = json_decode($requestBody);

            $switch = $requestParas->FTFPStatus;
            $ip = $requestParas->TFTPIp;
            $cycle = $requestParas->TFTPCycle;
            $ip_manu = $requestParas->TFTPIpManu;

            $cmd = "cluster-cfg set tftplog.tftp.ip_manu=".$ip;
            exec($cmd, $out, $return_var);
			exec("logger -t web -p 7 \"".$cmd."\"");
			
            $cmd = "/usr/sbin/upload_manu start";
            exec($cmd, $upload);
			exec("logger -t web -p 7 \"".$cmd."\"");

            if(0 === $return_var){
                $response = array(
                    'success' => true,
                    'result' => 'set TFTP info success!');
            }
            echo json_encode($response);
            $log_info = 'upload log to TFTP:'.$ip.' now success!';
            exec("logger -t web -p 5 \"".$log_info."\"");  
        }catch(Exception $e) {
            $error = array(
                    'success' => false,
                    'msg' => $e->getMessage() );
            echo json_encode($error);
            
            $log_info = 'upload log to TFTP error:'.$e->getMessage();
            exec("logger -t web -p 3 \"".$log_info."\"");      
        }
    }
);


$app->get(
	'/captive/getSwitch',
	function (){
		try {
			$cmd = 'cluster-cfg get captive_portal.eag.url_switch';
			exec($cmd,$execOut);
			if($execOut == null){
				$response = array(
							'success' => false,
							'result' => '');
				echo json_encode($response);
				return;
			}
			$result ='';
			foreach ($execOut as $value) {
				$result = $value;
			}
			$response = array(
						'success' => true,
						'result' => $result);
			echo json_encode($response);


		} catch (Exception $e){
			$error = array(
				'success' => false,
				'msg' => 'get switch status fault!'
			);
			echo json_encode($error);
		}
	}
);


$app->get(
	'/captive/getUrl',
	function (){
		try {
			$cmd = 'cluster-cfg get captive_portal.eag.url_string';
			exec($cmd,$execOut);
			if($execOut == null){
				$response = array(
							'success' => false,
							'result' => '');
				echo json_encode($response);
				return;
			}
			$result ='';
			foreach ($execOut as $value) {
				$result = $value;
			}
			$response = array(
						'success' => true,
						'result' => $result);
			echo json_encode($response);


		} catch (Exception $e){
			$error = array(
				'success' => false,
				'msg' => 'get switch status fault!'
			);
			echo json_encode($error);
		}
	}
);


$app->put(
	'/captive/setSwitch',
	function () use ($app){

    	$requestBody = $app->request()->getBody();
    	$requestParas = json_decode($requestBody);
    	$enable = $requestParas->enable;
    	if($enable){
    		$cmd = "cluster-cfg set captive_portal.eag.url_switch=1";
    	}else {
			$cmd = "cluster-cfg set captive_portal.eag.url_switch=0";
		}
		exec($cmd, $output, $return);
		if(0 == $return){
			reload_eag_config();
            $response = array (
                        'success' => true,
                        'msg' => 'set captive portal switch success! '

            );
			echo json_encode($response);

		}else {
			$response = array (
						'success' => false,
						'msg' => 'set captive portal switch fault! '

			);
			echo json_encode($response);
		}
	}
);

$app->put(
	'/captive/setUrl',
	function () use ($app){

    	$requestBody = $app->request()->getBody();
    	$requestParas = json_decode($requestBody);
    	$url = $requestParas->url;
    	$cmd = "cluster-cfg set captive_portal.eag.url_string=".$url;
		exec($cmd, $output, $return);
		if(0 == $return){
			reload_eag_config();

            $response = array (
                        'success' => true,
                        'msg' => 'set captive portal url success! '

            );
            echo json_encode($response);

		}else {
			$response = array (
						'success' => false,
						'msg' => 'set captive portal url fault! '

			);
			echo json_encode($response);
		}
	}
);
?>
