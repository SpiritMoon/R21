<?php
 
/**
*  check sessionId befor route
**/
$app->hook('slim.before.dispatch', function() use ($app) {
	//safed Routes
	$securedRoutes = array("/","/authentication/login","/logout","/authentication/syncSessionId","/authentication/sessionStatus","/checkstate","/downloadCertificate");

	if (in_array($app->request()->getPathInfo(),$securedRoutes) || $app->request()->isOptions()){
		return;
	}

	$updateTimestamp = true;
	$periodicRoutes = array("/pvcinfo","/haps","/wlans","/totalclientlist","/monitor/cpuAndMemUsage","/getapname");
	if (in_array($app->request()->getPathInfo(),$periodicRoutes)){
		$updateTimestamp = FALSE;
	}

	$isLogin = validateIsLogin($app->request,$updateTimestamp);
	if(FALSE == $isLogin){
		$app->halt(203, 'session or invalid, Does not respond to the operation!');
	}
 });

/**
 * [validateIsLogin description]
 * @param  [type] $request         [description]
 * @param  [type] $updateTimestamp [description]
 * @return [type] FALSE/TRUE
 */
function validateIsLogin($request,$updateTimestamp){
	try {
		$authorization = $request->headers->get('Authorization');	
		$key = 'sessionName ';//Authorization
		if(0 == strncmp($authorization, $key, strlen($key))){
			$sessionId = substr($authorization, strlen($key));
			
			if(!$sessionId){
				return FALSE;
			}	
			//check sessionId (must use UCI !!!!	)
			$users = array('Administrator', 'Viewer','GuestOperator');

			$return_var = FALSE;
  			foreach ($users as $user) {
  				unset($execOut);
  				$cmd = "uci get system.".$user.".sessionId;";
  				exec($cmd,$execOut,$reval);
				if($reval == 0 && $execOut[0] == $sessionId){//sessionId  isExist
					$return_var = true;
					if($updateTimestamp){//need updateTimestamp
						saveSessionIdValidity($user);
					}

					break;
				}
  			}
			return $return_var;
		}else{
			return FALSE;
		}	

	} catch(Exception $e) {
		echo($e);
		return FALSE;
	}	

};

/**
 * [checkSessionStatus description]
 * @param  [type] $request   [description]
 * @return [type] 0:isLogin  1:nosessionId 2:different sessionId 3:sessionId timeout
 */
function checkSessionStatus($request){
	try {
		$authorization = $request->headers->get('Authorization');	
		$key = 'sessionName ';//Authorization
		if(0 == strncmp($authorization, $key, strlen($key))){
			$sessionId = substr($authorization, strlen($key));
			
			if(!$sessionId){
				return 1;
			}	
			//check sessionId (must use UCI !!!!	)
			$users = array('Administrator', 'Viewer','GuestOperator');

			$return_var = 2;
			$now = time();
  			foreach ($users as $user) {
  				unset($execOut);
  				$cmd = "uci get system.".$user.".sessionId;uci get system.".$user.".sessionValidity;";
  				exec($cmd,$execOut,$reval);
				if($reval == 0 && $execOut[0] == $sessionId){//sessionId  isExist
					$sessionValidityInt =  intval($execOut[1]);
					if($now < $sessionValidityInt){//sessionId is validity
						$return_var = 0;

						//syncSessionId
						//if($syncSessionId){
							syncSessionId($user,$sessionId,0);
						//}
					}else{//sessionId is unvalidity
						$return_var = 3;
					}
					break;
				}
  			}
			return $return_var;
		}else{
			return 1;
		}	

	} catch(Exception $e) {
		echo($e);
		return 1;
	}	

};

/**
 * use uci savesessionIdValidity
 * @param  $username  
 **/
function saveSessionIdValidity($username){
	$now = time();
	$sessionValidity = 60*15;
	$sessionValidityPeriod = $now + $sessionValidity;
	
	$cmd = 'uci set system.'.$username.'.sessionValidity='.$sessionValidityPeriod.';uci commit;';
	exec($cmd);
}

/**
 * [updateSessionIdValidity description]
 * @param  [type] $request         [description]
 * @param  [type] $updateTimestamp [description]
 * @param  [type] $syncSessionId   [description]
 * @return [type] boolean
 */
function getUsernameBYsessionId($request){
	try {
		$authorization = $request->headers->get('Authorization');	
		$key = 'sessionName ';//Authorization
		if(0 == strncmp($authorization, $key, strlen($key))){
			$sessionId = substr($authorization, strlen($key));
			
			if(!$sessionId){
				return '';
			}
			//check sessionId (must use UCI !!!!	)
			$users = array('Administrator', 'Viewer','GuestOperator');

			$username = '';
			$now = time();
  			foreach ($users as $user) {
  				unset($execOut);
  				$cmd = "uci get system.".$user.".sessionId;";
  				exec($cmd,$execOut,$reval);
				if($reval == 0 && $execOut[0] == $sessionId){//sessionId  isExist
					$username = $user;
					break;
				}
  			}
			return $username;
		}else{
			return '';
		}	

	} catch(Exception $e) {
		echo($e);
		return '';
	}	

};

?>