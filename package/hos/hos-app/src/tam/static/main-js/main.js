angular.module('main', ["ui.bootstrap",
		"ui.router",
		"pascalprecht.translate",
		"ngCookies",
		"toastr",
		"nvd3ChartDirectives",
		"toggle-switch",
		"angularFileUpload",
		"wlan",
		"module.ap.apinfo",
		"module.wireless.rfManagement",
		"module.wireless.rogueAp",
		"module.wireless.others",
		"system",
		"module.terminal.acl",
		"module.terminal.authentication",
		"module.terminal.access",
		"module.client",
		"common",
		"monitor"
	])
	//<!-- toastr Config-->
	.config(['toastrConfig',function(toastrConfig) {
		angular.extend(toastrConfig, {
			allowHtml: true,
			closeButton: true,
			closeHtml: '<button>&times;</button>',
			containerId: 'toast-container',
			extendedTimeOut: 1000,
			iconClasses: {
				error: 'toast-error',
				info: 'toast-info',
				success: 'toast-success',
				warning: 'toast-warning'
			},
			messageClass: 'toast-message',
			positionClass: 'toast-top-right',
			preventOpenDuplicates: false,
			tapToDismiss: false,
			timeOut: 6000,
			titleClass: 'toast-title',
			toastClass: 'toast'
		});
	}])
/**config global filter,jump into login.html if returning 403 error**/
	.config(['$httpProvider',function($httpProvider) {

		$httpProvider.interceptors.push(function() {
			return {
				responseError: function(response) {
					if (response.status == 403) {

						//window.location.href = "/static/login.html";
					}
					return response;
				}
			}
		});
	}])

/** package $http，provide get，post method，add Authorization in header**/
	.factory('authentifiedRequest',['$http', function($http) {
		/**http**/
		var httpRequest = function(method, url, params, data, timeout, successCallback, errorCallback) {
			$http({
					method: method,
					url: url,
					params: params,
					data: data,
					timeout: timeout,
					headers: {
						'Content-Type': 'application/json',
						'Authorization': 'sessionName ' + window.localStorage.sessionId
					}
				}).success(successCallback).error(errorCallback);
		};

		return {
			get: function(url, params, successCallback, errorCallback) {
				httpRequest('get', url, params, null, 15000, successCallback, errorCallback);
			},
			put: function(url, params, data, successCallback, errorCallback) {
				httpRequest('put', url, params, data, 15000, successCallback, errorCallback);
			},
			post: function(url, params, data, successCallback, errorCallback) {
				httpRequest('post', url, params, data, 15000, successCallback, errorCallback);
			},
			delete: function(url, params, successCallback, errorCallback) {
				httpRequest('delete', url, params, data, 15000, successCallback, errorCallback);
			},
			request: httpRequest
		}
	}])
	/** operation Task**/
	.factory('task', ['$http', '$q', 'authentifiedRequest', 'InterService',function($http, $q, authentifiedRequest,InterService) {

		function Task(mac, ip, method, uri, params, data, defer, onCompletelistener,timeout) {
			this.mac = mac;
			this.ip = ip;
			this.method = method;
			this.uri = uri;
			this.params = params;
			this.data = data;
			this.defer = defer;
			this.onCompletelistener = onCompletelistener;
			this.timeout = timeout;
		}

		/**
		 * clone a task for reverting
		 */
		Task.prototype.clone = function() {
			return create(this.mac, this.ip, this.method, this.uri, this.params, this.data, this.onCompletelistener,this.timeout)
		};

		/**
		 * execute a task
		 */
		Task.prototype.execute = function(time) {
			time = time || 1; //execute times
			var self = this;
			var scheme = InterService.getProtocol()+"://";
			var port = ":"+InterService.getPort();
			var url = scheme + self.ip + port + self.uri
			
			// success Callback
			var successCallback = function(data, status) {

				//statement execute success
				var res = {
					'mac': self.mac,
					'ip': self.ip,
					'success': false,
					'msg': '',
					'result':[]
				};

				if (data == null || data == '') {//communication; fail
					res.success = false;
					res.msg = 'log_backendServer_error';
				}else{//success
					if(data.hasOwnProperty("success")){
						res.success = data.success;
					}
					
					if(data.hasOwnProperty("msg")){
						res.msg = data.msg;
					}

					if(data.hasOwnProperty("result")){
						res.result = data.result;
					}
				}

				self.defer.resolve(res);
			};

			// fail Callback
			var errorCallback = function(data, status) {
				var res = {
					'mac': self.mac,
					'ip': self.ip,
					'success': false,
					'msg': 'log_backendServer_error'
				};
				self.defer.reject(res);
			};
			
			//sent http request
			var timeout = 15000;//timeout time
			if(self.timeout != null){
				timeout = self.timeout;
			}
			authentifiedRequest.request(self.method, url, self.params, self.data, timeout, successCallback, errorCallback);

			return self.defer.promise.then(function(res) {
				self.onCompletelistener(res);
			}, function(res) {
				if (time < 3) {
					time++;
					// revert the task
					return self.clone().execute(time);
				} else {
					// task fail
					self.onCompletelistener(res);
					$q.reject(res);
				}
			});
		}

		/**
		 * create a task
		 */
		function create(mac, ip, method, uri, params, data, onCompletelistener,timeout) {
			var task = new Task(mac, ip, method.toLowerCase(), uri, params, data, $q.defer(), onCompletelistener,timeout);
			return task;
		}

		return {
			create: create
		}
	}])

/**
 * batch synchronous config
 */
.factory('batchSyncConfig', ['$translate', '$q', 'lockScreen', 'task', 'toastr', 'InterService', 'operationLog', function($translate, $q, lockScreen, task, toastr, InterService, operationLog) {

		//judge sth is array
		var isArray = function(o) {
			return Object.prototype.toString.call(o) === '[object Array]';
		}

		/**
		 * [tips for user]
		 * @param  {[string array]} msgs [string array]
		 */
		var tips = function(msgs) {
			var successNum = 0,
				faultNum = 0;
			var successMsg = $translate.instant('log_apNumber_success') +":";
			var faultMsg = $translate.instant('log_apNumber_fault') +":";
			var temp = "";
			angular.forEach(msgs, function(data) {
				if (data.success) {
					successNum++;
				} else {
					faultNum++;
					temp = temp + "<p>IP:" + data.ip + "&nbsp;" + $translate.instant('log_RSN')+ ":" + $translate.instant(data.msg) + "</p>";
				}
			});
			successMsg = "<p>" + successMsg + successNum + '</p>';
			faultMsg = "<p>" + faultMsg + faultNum + '</p>' + temp;

			var title = $translate.instant("log_operateResult")+":";
			toastr.info(successMsg + faultMsg, title);
		};

		/**
		 * [pushLog description]
		 */
		var pushLog = function(operationName,msgs,logtemp){
			var loginfo = new Array();
			
			angular.forEach(msgs, function(data) {

				var suc ='module_operate_failure';
				if(data.success){
					suc = 'module_operate_success';
				}
				var tmp = {'ip':data.ip,'success':suc,'msg':data.msg};
				loginfo.push(tmp);
			});
			operationLog.setLog(operationName,loginfo,logtemp);
		};

		return {
			//batch un-get request
			request: function(method, uri, params, httpData, callbackFunction,aps,operationName,timeout,logtemp) {
				//the contains store task result
				var msgs = [];

				function onCompletelistener(msg) {
					msgs.push(msg);
				}

				//lock screen start
				lockScreen.lock(timeout);
				
				var aplist = []
				if(aps == null){
					aplist = InterService.getCanConfigAps();
				}else{
					aplist = aps;
				}
				
				var tasks = [];
				angular.forEach(aplist, function(data) {
					var t = task.create(data.mac, data.ip, method, uri, params, httpData, onCompletelistener,timeout);
					tasks.push(t.execute());
				});

				if (tasks.length == 0) {
					//unlock screen
					lockScreen.unlock();

					//the notice  has no running ap that can be configged
	                var info = $translate.instant("log_noRunningAp_fault");

	                toastr.error(info);
	                
					if (callbackFunction != null) {
						callbackFunction();
					}
					return;
				}

				$q.all(tasks).then(function(res) {
					//unlock screen
					lockScreen.unlock();
					//notice
					tips(msgs)

					//set log
					if(operationName != null && operationName != ''){
						pushLog(operationName,msgs,logtemp);
					}
					
					//the follow-up operate ,if you have callback ,get callback
					if (callbackFunction != null) {
						callbackFunction();
					}
				});

			},
			//batch get request
			getAll: function( uri, params, callbackFunction,timeout) {
				//the contains of task result
				var results = [];

				//operation result
				function onCompletelistener(data) {
					if (data.success) {
						if(isArray(data.result)){
							Array.prototype.push.apply(results,data.result);
						}else{
							results.push(data.result);
						}
					}
				}

				var aplist = InterService.getApListInfo();
				var tasks = [];
				angular.forEach(aplist, function(data) {
					if (data.state == 3) { //running ap
						var t = task.create(data.mac, data.ip, 'get', uri, params, null, onCompletelistener,timeout);
						tasks.push(t.execute());
					}
				});

				if (tasks.length == 0) {
					if (callbackFunction != null) {
						return callbackFunction(results);
					}else{
						return ;
					}
				}

				$q.all(tasks).then(function(res) {
					//the follow-up operate ,if you have callback ,get callback
					if (callbackFunction != null) {
						callbackFunction(results);
					}
				});
			},

			//batch put request for batch update version
			putAll: function( uri, params, callbackFunction,timeout) {
				//the contains of task result
				var results = [];

				lockScreen.lock(timeout);
				//operation result
				function onCompletelistener(data) {
					if (data.success) {
						if(isArray(data.result)){
							Array.prototype.push.apply(results,data.result);
						}else{
							results.push(data.result);
						}
					}
				}

				var aplist = InterService.getApListInfo();
				var tasks = [];
				angular.forEach(aplist, function(data) {
					if (data.state == 3) { //running ap
						var t = task.create(data.mac, data.ip, 'put', uri, null, params, onCompletelistener,timeout);
						tasks.push(t.execute());
					}
				});

				if (tasks.length == 0) {
					if (callbackFunction != null) {
						return callbackFunction(results);
					}else{
						return ;
					}
				}

				$q.all(tasks).then(function(res) {
					//the follow-up operate ,if you have callback ,get callback
					if (callbackFunction != null) {
						callbackFunction(results);
					}
				});
			}
		};
	}])

	/**
	 * [package lock screen ]
	 */
	.factory('lockScreen', ['$timeout', '$rootScope', function($timeout, $rootScope) {
		var timeout = null;

		var time_out_func = function(time){
			if (timeout)
				$timeout.cancel(timeout);

			timeout = $timeout(function() {
				$rootScope.loading = false;
			}, time);
		};

		/**
		 * [unlock description]
		 */
		var unlock = function() {
			time_out_func(1000);
		};

		/**
		 * [lock description]
		 */
		var lock = function(timeout) {
			$rootScope.loading = true;
			if(timeout == null){
				time_out_func(15000);
			}else{
				time_out_func(timeout);
			}
		};

		return {
			lock: lock,
			unlock: unlock
		}
	}])
	/**
	 * [package lock screen ]
	 */
	.service('hanCrypto', [ function() {
		var vm = this;

		/**
		 * encoder
		 */
		vm.encoder = function(str) {
			if(str == null || str == ''){
				return str;
			}
			return BASE64.encoder(str);
		};

		/**
		 * decoder
		 */
		vm.decoder = function(str) {
			if(str == null || str == ''){
				return str;
			}

			var unicode = BASE64.decoder(str);//返回会解码后的unicode码数组。
			var tt = '';
			for(var i = 0 , len =  unicode.length ; i < len ;++i){
				  tt += String.fromCharCode(unicode[i]);
			}
			return tt;
		};

	}])	

	/**
	 * operationLog
	 */
	.factory('operationLog', [ function() {
		var logs = new Array();

		/**
		 * getLogs
		 */
		var getLogs = function() {
			return logs;
		};

		/**
		 * setLog
		 */
		var setLog = function(logname,loginfo,logtemp) {
			var d = new Date();
			var log = {'logname':'','loginfo':'','datetime':'','logtemp':''};
			log.logname = logname;
			log.loginfo = loginfo;
			log.logtemp = logtemp;
			log.datetime = d;
			if(logs.length == 10){
				logs.shift();
			}
			logs.push(log);
		};

		/**
		 * cleanLogs
		 */
		var cleanLogs = function(log) {
			logs = new Array();
		};

		return {
			getLogs: getLogs,
			setLog: setLog,
			cleanLogs:cleanLogs
		}
	}])	
	/**
	 * modal
	 */
	.factory('singleModal', ['$modal', function($modal) {
		var vm = this;
		vm.modal = null;
		vm.draggable = function(){
            $(".modal-content").draggable({ 
            	handle: ".modal-header",
			    cursor: 'move',   
			    refreshPositions: false  
			});  
		};

		return {
			open: function(param,result_fc,reason_fc) {

				if (vm.modal != null) {
					return null;
				}
				vm.modal = $modal.open(param);

				vm.modal.result.then(function(result) {
					vm.modal = null;
					if(result_fc!= null){
						result_fc(result);
					}				
				},function(reason){
					vm.modal = null;
					if(reason_fc!= null){
						reason_fc(reason);
					}				
				});
				
				vm.modal.opened.then(function() { 
                    setTimeout(vm.draggable,3000);
                });  

				return vm.modal;
			}
		}
	}])
.service('InterService',['authentifiedRequest', '$cookieStore', 'clientService', '$translate',function(authentifiedRequest, $cookieStore, clientService,$translate) {
	var vm = this;
	vm.aplistinfo = [];
	vm.countryCode = "";
	vm.PVCinfo = "";
	vm.countryCodeInfo = "";
	vm.port = "";
	vm.protocol = "";
	vm.getPort = function () {
		return vm.port;
	}
	vm.setPort = function (port) {
		vm.port = port;
	}
	vm.getProtocol = function () {
		return vm.protocol;
	}
	vm.setProtocol = function (protocol) {
		vm.protocol = protocol;
	}
	vm.getCountryCodeInfo = function(){
		return vm.countryCodeInfo;
	}
	vm.setCountryCodeInfo = function(countrycode){
		vm.countryCodeInfo = countrycode;
	}
	vm.setCountryCode = function (countryCode) {
		vm.countryCode = countryCode;
	}
	vm.getCountryCode = function () {
		return vm.countryCode;
	}

	vm.getPVCinfo = function(x) {
		return vm.PVCinfo;
	}

	vm.setPVCinfo = function(x) {
		vm.PVCinfo = x;
	}

	vm.getApListInfo = function() {
		return vm.aplistinfo;
	}

	vm.getCanConfigAps = function() {
		var aps = vm.aplistinfo;
		var tempAps = [];
        angular.forEach(aps, function(data) {
            if (data.state == 3 || data.state == 2) { //running/Initializing ap
                tempAps.push(data);
            }
        });
		return tempAps;
	}

	vm.setApListInfo = function(x) {
			vm.aplistinfo = x;
		}

	vm.skin = {
		isPurple: false,
		isBlue: true,
		imageUrl: 'assets/images/blue.png',
		isSelectSkin: false
	};
	vm.getSkin = function(){
		if($cookieStore.get('skin') == null || $cookieStore.get('skin') == 'blue'){
			vm.skin.isPurple = false;
			vm.skin.isBlue = true;
			vm.skin.imageUrl = 'assets/images/blue.png';
		}
		else if($cookieStore.get('skin') == 'purple'){
			vm.skin.isPurple = true;
			vm.skin.isBlue = false;
			vm.skin.imageUrl = 'assets/images/purple.png';
		}
	};
	vm.changeSelectedBlueToPurple = function() {
		var system_title_bg = $("#system_title_bg");
		if (system_title_bg.hasClass("unfoldedlv1menublue")) {
			system_title_bg.removeClass("unfoldedlv1menublue").addClass("unfoldedlv1menupurple");
			$("#sys_left_iconbg").removeClass("selected_icon_blue").addClass("selected_icon_purple");
			$("#sys_right_iconbg").removeClass("selected_icon_blue").addClass("selected_icon_purple");
		}
		var wireless_title_bg = $("#wireless_title_bg");
		if (wireless_title_bg.hasClass("unfoldedlv1menublue")) {
			wireless_title_bg.removeClass("unfoldedlv1menublue").addClass("unfoldedlv1menupurple");
			$("#wire_left_iconbg").removeClass("selected_icon_blue").addClass("selected_icon_purple");
			$("#wire_right_iconbg").removeClass("selected_icon_blue").addClass("selected_icon_purple");
		}
		var access_title_bg = $("#access_title_bg");
		if (access_title_bg.hasClass("unfoldedlv1menublue")) {
			access_title_bg.removeClass("unfoldedlv1menublue").addClass("unfoldedlv1menupurple");
			$("#acc_left_iconbg").removeClass("selected_icon_blue").addClass("selected_icon_purple");
			$("#acc_right_iconbg").removeClass("selected_icon_blue").addClass("selected_icon_purple");
		}
	};
	vm.changeSelectedPurpleToBlue = function() {
		var system_title_bg = $("#system_title_bg");
		if (system_title_bg.hasClass("unfoldedlv1menupurple")) {
			system_title_bg.removeClass("unfoldedlv1menupurple").addClass("unfoldedlv1menublue");
			$("#sys_left_iconbg").removeClass("selected_icon_purple").addClass("selected_icon_blue");
			$("#sys_right_iconbg").removeClass("selected_icon_purple").addClass("selected_icon_blue");
		}
		var wireless_title_bg = $("#wireless_title_bg");
		if (wireless_title_bg.hasClass("unfoldedlv1menupurple")) {
			wireless_title_bg.removeClass("unfoldedlv1menupurple").addClass("unfoldedlv1menublue");
			$("#wire_left_iconbg").removeClass("selected_icon_purple").addClass("selected_icon_blue");
			$("#wire_right_iconbg").removeClass("selected_icon_purple").addClass("selected_icon_blue");
		}
		var access_title_bg = $("#access_title_bg");
		if (access_title_bg.hasClass("unfoldedlv1menupurple")) {
			access_title_bg.removeClass("unfoldedlv1menupurple").addClass("unfoldedlv1menublue");
			$("#acc_left_iconbg").removeClass("selected_icon_purple").addClass("selected_icon_blue");
			$("#acc_right_iconbg").removeClass("selected_icon_purple").addClass("selected_icon_blue");
		}
	};
	vm.setSkin = function(color) {
		if (color == 'purple') {
			$cookieStore.put('skin', 'purple');
			vm.skin.isSelectSkin = false;
			vm.skin.isPurple = true;
			vm.skin.isBlue = false;
			vm.skin.imageUrl = 'assets/images/purple.png';
			vm.changeSelectedBlueToPurple();
		} else if (color == 'blue') {
			$cookieStore.put('skin', 'blue');
			vm.skin.isSelectSkin = false;
			vm.skin.isPurple = false;
			vm.skin.isBlue = true;
			vm.skin.imageUrl = 'assets/images/blue.png';
			vm.changeSelectedPurpleToBlue();
		}
	};

	vm.pattern = {
		"passwordInfo":"/^[^`=\"\']{4,16}$/",
		"ldu4To16": "/^[\\w]{4,16}$/",
		"ldu1to10": "/^[\\w]{1,10}$/",
		"ldu1to20": "/^[\\w]{1,20}$/",
		"ldu1to25": "/^[\\w]{1,25}$/",
		"ldu1to30": "/^[\\w]{1,30}$/",
		"ldu1to32": "/^[\\w]{1,32}$/",
		"ldu1to32Demo":"/^[^`=\"\']{1,32}$/",
		"ldu8to63":"/^[\\w]{8,63}$/",
		"ldu8to63Demo":"/^[^`=\"\']{8,63}$/",
		"GroupName":"/^[\\w-]{1,25}$/",
		"normalMAC": "/^([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})$/",
		"AuthMAC": "/^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})?$/",
		"WhitelistMAC":"/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){0,5}$/",
		"Hex64char":"/^[a-fA-F\\d]{64}$/",
		"Hex64charDemo":"/^[a-fA-F\\d]{64}$/",
		"IP": '/^(([1-9])|([1-9]\\d)|(1\\d\\d)|(2[0-4]\\d)|(25[0-5]))(\\.(\\d|([1-9]\\d)|1\\d\\d|2[0-4]\\d|25[0-5])){3}$/',
		"IPMask": "/^(([1-9])|([1-9]\\d)|1\\d\\d|2[0-4]\\d|25[0-5])(\\.(\\d|([1-9]\\d)|1\\d\\d|2[0-4]\\d|25[0-5])){3}(\/([1-9]|[1-2][0-9]|3[0-2]))?$/",
		"LetterDigit4To8": "/^[a-zA-Z\\d]{4,8}$/",
		"IPAndDomain": "/^((25[0-5])|(2[0-4]\\d)|(1\\d\\d)|([1-9]\\d)|([1-9]))(\\.((25[0-5])|(2[0-4]\\d)|(1\\d\\d)|([1-9]\\d)|\\d)){3}$|^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}$/",
		//"exceptBlank1To32": "/^[^\\s]{1,32}$/",
		"exceptBlank1To32": "/^[\\x00-\\xff]{1,32}$/",
		"AuthPort":"/^(^[1-9]\\d{0,3}$)|(^[1-5]\\d{4}$)|(^6[0-4][\\d]{3}$)|(^65[0-4][\\d]{2}$)|(^655[0-2][\\d]|6553[0-5]$)$/",
		"GroupID":"/^[1-9]\\d{0,3}$/",
		"VLANID":"/^(^[0-9]$)|(^[1-9]\\d{1,2}$)|(^[1,-3]\\d{3}$)|(^40[0-8]\\d$)|(^409[0-4]$)$/",
		"Stream":"/^(^[0-9]\\d{0,3}$)|(^[1-5]\\d{4}$)|(^6[0-4][\\d]{3}$)|(^65[0-4][\\d]{2}$)|(^655[0-2][\\d]|6553[0-6]$)$/",
		"maxClients":"/^(^[1-9]\\d{0,1}$)|(^1[0,1]\\d$)|(^120$)$/",
		"RSSIThreshold":"/^(^[0-9]$)|(^[1-9]\\d$)|100$/",
		"FirstName":"/^[a-zA-Z-._\\s]{0,35}$/",
		"LastName":"/^[a-zA-Z-._\\s]{0,35}$/",
		//"Phone":"/^[\\d-]{0,20}$/",
		"Phone":"/^(?!-)[\\d-]{0,20}$/",
		"Mail":"/^\\w[-\\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}$/",
		"Company":"/^[a-zA-Z-_.,&\\s]{0,64}$/",
		"APName": "/^[\\w\.:-]{1,20}$/"
	};
	vm.errorTip = {
		"validIP": $translate.instant("validIP"),
		"validIPOrDomain":$translate.instant("validIPOrDomain"),
		"validMac": $translate.instant("validMac"),
		"positiveInteger":$translate.instant("positiveInteger"),
		"passNotSame":$translate.instant("passNotSame"),
		"Hexchar64":$translate.instant("Hexchar64"),
		"ldu":$translate.instant("ldu"),
		"wlanNameTip":$translate.instant("wlanNameTip"),
		"validFTP": $translate.instant("validFTP"),
		"Hexchar64Demo":$translate.instant("Hexchar64Demo"),
		"APName":$translate.instant("APName")
	};

	vm.validIP = function () {
		return $translate.instant("validIP");
	}
	vm.validIPOrDomain = function () {
		return $translate.instant("validIPOrDomain");
	}
	vm.validMac = function () {
		return $translate.instant("validMac");
	}
	vm.positiveInteger = function () {
		return $translate.instant("positiveInteger");
	}
	vm.passNotSame = function () {
		return $translate.instant("passNotSame");
	}
	vm.Hexchar64 = function () {
		return $translate.instant("Hexchar64");
	}
	vm.ldu = function () {
		return $translate.instant("ldu");
	}
	vm.wlanNameTip = function () {
		return $translate.instant("wlanNameTip");
	}
	vm.validFTP = function () {
		return $translate.instant("validFTP");
	}
	vm.Hexchar64Demo = function () {
		return $translate.instant("Hexchar64Demo");
	}
	vm.APName = function () {
		return $translate.instant("APName");
	}
	vm.lduLengthRangeTip = function(minlength, maxlength){
		return $translate.instant("Please enter") + minlength + $translate.instant("To") + maxlength +  $translate.instant("underline");
	};
	vm.lduLengthRangeTipDemo = function(minlength, maxlength){
		return $translate.instant("Please enter") + minlength + $translate.instant("To") + maxlength + $translate.instant("notContain");
	};
	vm.valueNotNull = function(name){
		return $translate.instant("The") + name + $translate.instant("notEmpty");
	};
	vm.numRange = function(name, startValue, endValue){
		//return "Please input a number between " + startValue + " and " + endValue;
		return $translate.instant("The") + name + $translate.instant("BETWEEN") + startValue + $translate.instant("AND") + endValue;
	};
	vm.valueLengthRange = function(minlength, maxlength){
		return $translate.instant("Pbetween") + minlength + $translate.instant("To") + maxlength;
	};
	vm.LetterDigitErrorTip = function(minlength, maxlength){
		return $translate.instant("Please enter") + minlength +$translate.instant("To")+ maxlength + $translate.instant("letterDegits");
	};

}])

.service('clientService', [function(){
	var vm = this;
    vm.ClientList = [];
 
	vm.getClientList = function(){
		return vm.ClientList;
	}
	vm.setClientList = function(client){
		vm.ClientList = [];
		vm.ClientList = client;
	}
	
	vm.getWlanClient = function(wlan){
		var filterClientList =[];
		if(wlan == ""){
			return vm.ClientList;
		}
		angular.forEach(vm.ClientList, function(data){
			if(data.WLAN == wlan){
				filterClientList.push(data);
			}
		});
		return filterClientList;
	}
	
	vm.getApClient = function(apmac){
		var filterClientList =[];
		if(apmac == ""){
			return vm.ClientList;
		}

		angular.forEach(vm.ClientList, function(data){
			if(data.AP == apmac){
				filterClientList.push(data);
			}
		});
		
		return filterClientList;
	}
}])
.config(['$translateProvider', function($translateProvider){

	//international json file path  in nugix
	$translateProvider.useStaticFilesLoader({
		prefix: '/static/data/',
		suffix: '.json'
	});

	$translateProvider.preferredLanguage('en_US');
	$translateProvider.useCookieStorage();
}])
.directive("repeat", [function () {
	return {
		restrict: 'A',
		require: "ngModel",
		link: function (scope, element, attrs, ctrl) {
			if (ctrl) {
				var otherInput = element.inheritedData("$formController")[attrs.repeat];

				var repeatValidator = function (value) {
					var validity = value === otherInput.$viewValue;
					ctrl.$setValidity("repeat", validity);
					return validity ? value : undefined;
				};

				ctrl.$parsers.push(repeatValidator);
				ctrl.$formatters.push(repeatValidator);

				otherInput.$parsers.push(function (value) {
					ctrl.$setValidity("repeat", value === ctrl.$viewValue);
					return value;
				});
			}
		}
	};
}]) .directive('integerport',[function(){
	return {
		restrict: 'A',
		link:function(scope,ele,attrs){
			ele.bind('paste',function(event){
				var e=event || window.event;
				if(e.charCode){
					e.preventDefault();
				}else{
					e.returnValue=false;
				}

 			});
			ele.bind("keydown",function(event){
				var e=event || window.event;
				if(e.keyCode == 13) {
					e.keyCode = 9;
				}else if(e.charCode == 13){
					e.charCode=9;
				}
			});
			ele.bind("keypress",function(event){
				var e=event || window.event;
				if(e.charCode && (e.charCode<48 || e.charCode >57)){
					e.preventDefault();
				}
				if (e.keyCode<48 || e.keyCode>57) {
					e.returnValue=false;
				}
			});
		}
	}}])
;
