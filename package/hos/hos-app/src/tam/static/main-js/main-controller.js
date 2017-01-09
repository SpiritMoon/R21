angular.module('main')
	.run(['$rootScope','$interval','toastr','InterService','authentifiedRequest','permissions','clientService','$location',function($rootScope,$interval,toastr,InterService,authentifiedRequest,permissions,clientService,$location) {
		//init haplist
		$.ajax({
			async: false,
			type: "get",
			url: "/haps",
			timeout: 15000,
			dataType: 'json',
			headers: {
					'Authorization': 'sessionName ' + window.localStorage.sessionId
			},
			error: function() {
				console.error('inithaps fail');
			},
			success: function(data) {
				if (data != null && data.result != null && data.success) {
					//filter the ap that status is not working
					var flag=false;
		        	for(var i=data.result.length; i> 0 ;i-- ){

                        if((!data.result[i-1].hasOwnProperty('name'))||(data.result[i-1].name=='') || (data.result[i-1].name ==null)){
                            data.result[i-1].apname = data.result[i-1].mac;
                        }else{
                            data.result[i-1].apname = data.result[i-1].name;
                        }

						if(!data.result[i-1].hasOwnProperty('version')){
                            data.result[i-1].version = " ";
						}

		                if(data.result[i-1].state == 0){
		                    //data.result.splice(i-1, 1);
							data.result[i-1].state="1";
		                }
						var apsClients = clientService.getApClient(data.result[i-1].mac);
						if(null != apsClients){
							data.result[i-1].clients = apsClients.length;
						}else {
							data.result[i-1].clients = 0;
						}
						if(!flag){
							if(data.result[i-1].role==1){
								InterService.setPVCinfo(data.result[i-1].ip);
								flag=true;
							}
						}
		            }
					InterService.setApListInfo(data.result);
				} else {
					console.error('inithaps fail');
				}				
			}
		});

		//lock screen initialization
		$rootScope.loading = false;

		//permission initialization
		permissions.setPermissions(window.localStorage.username);

		//get country code
		authentifiedRequest.get('/other/countryCode', null, function(data){
			if(data != null && data.success){
				InterService.setCountryCode(data.countryFlag);
			}
		});
		authentifiedRequest.get('/other/systemInfo', null, function(response) {
			if (response.success) {
				var data = response.result;
				InterService.setCountryCodeInfo(data.countryCode);
			}
		}, function() {});

		InterService.setPort($location.port());
		InterService.setProtocol($location.protocol());
	}])
	.controller('mainController', ['$rootScope','$scope','$translate', 'singleModal', 'InterService', '$interval', '$translate','ClusterService', 'monitorService','$cookieStore','operationLog', 'APService', 'authentifiedRequest','$modal', function($rootScope,$scope,$translate, singleModal, InterService, $interval, $translate,ClusterService, monitorService,$cookieStore,operationLog, APService, authentifiedRequest, $modal) {

		//get protocal and port

		//control the change  of international language include chinese and english
		$scope.isEnglish  = true;
		$scope.isChiness = false;
		$scope.isDeutsch = false;
		$scope.isBoth = false;

		//polling cycle selected value
		$scope.pollingCycleSelected = {};

		//rolling cycle
		$scope.pollingCycles = [{
			name: "30s"
		}, {
			name: "60s"
		}, {
			name: "120s"
		}];

		getLang();
		//refresh  page  getting the language and polling cycle that user select
		function getLang (){
			//语言
			if($cookieStore.get("lang") == null||$cookieStore.get("lang") == "en"){
				$scope.isEnglish  = true;
				$scope.isChiness = false;
				$scope.isBoth = false;
				$scope.isDeutsch = false;
			}else if($cookieStore.get("lang") == "zh"){
				$scope.isEnglish  = false;
				$scope.isChiness = true;
				$scope.isBoth = false;
				$scope.isDeutsch = false;
			}else if($cookieStore.get("lang") == "de"){
				$scope.isEnglish  = false;
				$scope.isChiness = false;
				$scope.isBoth = false;
				$scope.isDeutsch = true;
			}

			//polling cycle
			if($cookieStore.get("cycleName") == null||$cookieStore.get("cycleName") == "30s"){
				$cookieStore.put("cycleName","30s");
				$scope.pollingCycleSelected = $scope.pollingCycles[0];
			}else if($cookieStore.get("cycleName") == "60s"){
				$scope.pollingCycleSelected = $scope.pollingCycles[1];
			}else if($cookieStore.get("cycleName") == "120s"){
				$scope.pollingCycleSelected = $scope.pollingCycles[2];
			}

			/* skin */
			InterService.getSkin();
		}

		//set user select the language
		$scope.langInterval = {};
		$scope.setLang = function(langKeyNum) {
			var langKey = "en_US";
			switch (langKeyNum){
				case 0:
					langKey = "en_US";
					$cookieStore.put("lang","en");
					$scope.isEnglish  = false;
					$scope.isChiness = false;
					$scope.isBoth = true;
					$scope.isDeutsch = false;
					$scope.langInterval = $interval(function(){
						$scope.isBoth=false;$scope.isEnglish=true;$scope.isChiness=false;$scope.isDeutsch = false;
					}, 3000, 1);
					break;
				case 1:
					langKey = "zh_CH";
					$cookieStore.put("lang","zh");
					$scope.isEnglish  = false;
					$scope.isChiness = false;
					$scope.isBoth = true;
					$scope.langInterval = $interval(function(){
						$scope.isBoth=false;$scope.isEnglish=false;$scope.isChiness=true;$scope.isDeutsch = false;
					}, 3000, 1);
					break;
				case 2:
					langKey = "de_DE";
					$cookieStore.put("lang","de");
					$scope.isEnglish  = false;
					$scope.isChiness = false;
					$scope.isBoth = true;
					$scope.isDeutsch = false;
					$scope.langInterval = $interval(function(){
						$scope.isBoth=false;$scope.isEnglish=false;$scope.isChiness=false;$scope.isDeutsch = true;
					}, 3000, 1);
					break;
				case 3:
					$interval.cancel($scope.langInterval);
					langKey = "en_US";
					$cookieStore.put("lang","en");
					$scope.isEnglish  = true;
					$scope.isChiness = false;
					$scope.isBoth = false;
					$scope.isDeutsch = false;
					break;
				case 4:
					$interval.cancel($scope.langInterval);
					langKey = "zh_CH";
					$cookieStore.put("lang","zh");
					$scope.isEnglish  = false;
					$scope.isChiness = true;
					$scope.isBoth = false;
					$scope.isDeutsch = false;
					break;
				case 5:
					$interval.cancel($scope.langInterval);
					langKey = "de_DE";
					$cookieStore.put("lang","de");
					$scope.isEnglish  = false;
					$scope.isChiness = false;
					$scope.isBoth = false;
					$scope.isDeutsch = true;
					break;
			}
			$translate.use(langKey);
		};
		//log
		$scope.logs = [];
		$scope.logs_temp = [];
		$scope.logTime ={};
		
		$scope.logClick = function (flag) {
			//get data
			$scope.logs_temp = angular.copy(operationLog.getLogs());
			$scope.logs =$scope.logs_temp.reverse();
			$(".pos-rts").show(1000);
			logTimer();
		}
		
		$scope.logLeave = function () {
			$interval.cancel($scope.logTime);
			$(".pos-rts").hide(1000);
		}

		$scope.cancelInterval = function () {
			$interval.cancel($scope.logTime);
		}

		function logTimer(){
			var timeTemp = $interval(function () {
				$(".pos-rts").hide(1000);
				$interval.cancel($scope.logTime);
			},3000);
			$scope.logTime = timeTemp;
		}

		$scope.userName = window.localStorage.username;
		$scope.InterService = InterService;
		$scope.ClusterService = ClusterService;
		$scope.skin = InterService.skin;
		$scope.setSkin = InterService.setSkin;
		$scope.clusterInfo={};

		//Polling initialization invoking
		$scope.wlanManagement = {};
		$scope.clientManagement = {};

		$scope.skinInterval = {};
		$scope.showSkinOption = function() {
			$scope.skin.isSelectSkin = true;
			$scope.skinInterval = $interval(function(){
				$scope.skin.isSelectSkin = false;
			},3000,1)
		};
		$scope.helpTip = {
			isEabled: false
		};
		$scope.helpButtonTip = {
			title:$translate.instant("mouseMovedHelpViewInfo")
		};

		$scope.$watch('ClusterService.ClusterinfoSer', function(newVal, oldVal) {
			if (newVal !== oldVal) {
				$scope.clusterInfo = ClusterService.getClusterinfoSer();
				//初始化monitor
				$scope.showMonitorData ($scope.clusterInfo.cluster_name);
			}
		}, true);

		//initialization refresh

		$scope.clientCallback = function(){
			//get wlan list
			$scope.wlanManagement.query();

			//get ap list
			APService.HttpGetApListInfo(function(){
				$scope.$broadcast('to-aplist-child', true);
			});


			//monitor
			monitorService.updateChartview();
		};

		var pollingTime = parseInt($cookieStore.get("cycleName").trim());
		var timer=null;
		var seStateTimer=null;

		$rootScope.$on('modal-to-main', function(event,data) {
			if(timer != null){
				$interval.cancel(timer);
			}
			if(seStateTimer != null){
				$interval.cancel(seStateTimer);
			}
        });

        APService.HttpGetApListInfo(function(){
			$scope.$broadcast('to-aplist-child', true);
		});

		//Open interval
		function pollingCycle(pollingTime) {

			var timerDemo = $interval(function() {

				//get client list
				$scope.clientManagement.query($scope.clientCallback);
				APService.HttpGetPvcInfo();



				// //get wlan list
				// $scope.wlanManagement.query();


				// //get ap list
				// InterService.HttpGetApListInfo(null);
				// //getaplistinfo();


				// //get client list
				// $scope.clientManagement.query();

				// //monitor
				// monitorService.updateChartview();
			}, pollingTime * 1000);
			timer = timerDemo;

			$scope.prompt = null;
			var sessionTimer = $interval(function() {
				authentifiedRequest.post('/authentication/sessionStatus', null,null, function(data){
					if (data != null  && data.success) {
						//0:isLogin  1:nosessionId 2:different sessionId 3:sessionId timeout
						if(data.flag == 0){
							return;
						}

						if($scope.prompt != null){
							return;
						}

						$scope.prompt = $modal.open({
							templateUrl: 'logout-prompt.html',
							controller: "logoutPromptCtrl",
							size: 'md',
							backdrop: 'static',
							keyboard: false,
							resolve : {
								flag : function() {
									return data.flag;
								}
							}
						});

						$scope.prompt.result.then(function(result) {
							$scope.prompt = null;
						}, function(reason) {
							$scope.prompt = null;
						});

					}

				}, function(){});
			}, 30000);

			seStateTimer = sessionTimer;
		}

		pollingCycle(pollingTime);
		//change polling cycle time
		$scope.pollingChange = function() {
			//delete the current interval
			$interval.cancel(timer);
			var cycleName = this.pollingCycleSelected.name;
			$cookieStore.put("cycleName",cycleName);
			pollingTime = parseInt(cycleName.replace("s", "").trim());
			pollingCycle(pollingTime);
		}

		/**
		 * Monitor
		 */
		$scope.showMonitorData = function(clusterName){
			var title = $translate.instant("ClusterGroup")+clusterName;
			monitorService.changeObser('cluster', null, title);
			//$scope.clientManagement.changeClient('cluster', "");
			$scope.clientManagement.changeClient('cluster', clusterName);

		};

		//about
		$scope.showAbout = function() {
			singleModal.open({
				templateUrl: 'common/about/about.html',
				controller: 'aboutContronller',
				size: 'md',
				backdrop: true
			});
		}
		//tools
		$scope.showTools = function() {
			singleModal.open({
				templateUrl: 'common/tools/tools.html',
				controller: 'toolsContronller',
				size: 'lg',
				backdrop: true
			});
		}

		//PMD
		$scope.showPMD = function () {
			singleModal.open({
				templateUrl: 'common/pmd/pmd.html',
				controller: 'pmdContronller',
				size: 'md',
				backdrop: true
			});
		}

		//help
		$scope.showHelp = function() {
			$scope.helpTip.isEabled = !$scope.helpTip.isEabled;
			/*Help is open or close*/
			if($scope.helpTip.isEabled == true){
				$scope.helpButtonTip.title = $translate.instant("clickDisabledHelp");
			}
			else{
				$scope.helpButtonTip.title = $translate.instant("mouseMoveHelpCheckHelp");
			}
		};
		/*toggle first level title color and it's right icon*/
		$scope.getColorClass = function(){
			if($scope.skin.isPurple == true){
				$scope.menu_class = "unfoldedlv1menupurple";
				$scope.icon_bg = "selected_icon_purple";
			}
			else {
				 $scope.menu_class = "unfoldedlv1menublue";
				 $scope.icon_bg = "selected_icon_blue";
			}
		};

		$("#system_menu").click(function() {
			$scope.getColorClass();
			var result = $("#collapsesystem").hasClass("blackmenu");
			/*selected status*/
			if (result == true) {
				$("#collapsesystem").toggleClass('blackmenu', false);
				$("#system_icon").attr("src", "assets/images/up.png");
				$("#collapsewireless").toggleClass('blackmenu', true);
				$("#wireless_icon").attr("src", "assets/images/down.png");
				$("#collapseaccess").toggleClass('blackmenu', true);
				$("#access_icon").attr("src", "assets/images/down.png");

				$("#system_title_bg").addClass($scope.menu_class);
				$("#sys_left_iconbg").addClass($scope.icon_bg);
				$("#sys_right_iconbg").addClass($scope.icon_bg);
				$("#wireless_title_bg").removeClass($scope.menu_class);
				$("#wire_left_iconbg").removeClass($scope.icon_bg);
				$("#wire_right_iconbg").removeClass($scope.icon_bg);
				$("#access_title_bg").removeClass($scope.menu_class);
				$("#acc_left_iconbg").removeClass($scope.icon_bg);
				$("#acc_right_iconbg").removeClass($scope.icon_bg);
			} else {
				$("#system_icon").attr("src", "assets/images/down.png");
				$("#collapsesystem").toggleClass('blackmenu', true);
				$("#system_title_bg").removeClass($scope.menu_class);
				$("#sys_left_iconbg").removeClass($scope.icon_bg);
				$("#sys_right_iconbg").removeClass($scope.icon_bg);
			}

		});
		$("#wireless_menu").click(function() {
			$scope.getColorClass();
			var result = $("#collapsewireless").hasClass("blackmenu");
			if (result == true) {
				$("#collapsewireless").toggleClass('blackmenu', false);
				$("#wireless_icon").attr("src", "assets/images/up.png");
				$("#collapsesystem").toggleClass('blackmenu', true);
				$("#system_icon").attr("src", "assets/images/down.png");
				$("#collapseaccess").toggleClass('blackmenu', true);
				$("#access_icon").attr("src", "assets/images/down.png");

				$("#system_title_bg").removeClass($scope.menu_class);
				$("#sys_left_iconbg").removeClass($scope.icon_bg);
				$("#sys_right_iconbg").removeClass($scope.icon_bg);
				$("#wireless_title_bg").addClass($scope.menu_class);
				$("#wire_left_iconbg").addClass($scope.icon_bg);
				$("#wire_right_iconbg").addClass($scope.icon_bg);
				$("#access_title_bg").removeClass($scope.menu_class);
				$("#acc_left_iconbg").removeClass($scope.icon_bg);
				$("#acc_right_iconbg").removeClass($scope.icon_bg);
			} else {
				$("#wireless_icon").attr("src", "assets/images/down.png");
				$("#collapsewireless").toggleClass('blackmenu', true);
				$("#wireless_title_bg").removeClass($scope.menu_class);
				$("#wire_left_iconbg").removeClass($scope.icon_bg);
				$("#wire_right_iconbg").removeClass($scope.icon_bg);
			}
		});
		$("#access_menu").click(function() {
			$scope.getColorClass();
			var result = $("#collapseaccess").hasClass("blackmenu");
			if (result == true) {
				$("#collapseaccess").toggleClass('blackmenu', false);
				$("#access_icon").attr("src", "assets/images/up.png");
				$("#collapsesystem").toggleClass('blackmenu', true);
				$("#system_icon").attr("src", "assets/images/down.png");
				$("#collapsewireless").toggleClass('blackmenu', true);
				$("#wireless_icon").attr("src", "assets/images/down.png");

				$("#system_title_bg").removeClass($scope.menu_class);
				$("#sys_left_iconbg").removeClass($scope.icon_bg);
				$("#sys_right_iconbg").removeClass($scope.icon_bg);
				$("#wireless_title_bg").removeClass($scope.menu_class);
				$("#wire_left_iconbg").removeClass($scope.icon_bg);
				$("#wire_right_iconbg").removeClass($scope.icon_bg);
				$("#access_title_bg").addClass($scope.menu_class);
				$("#acc_left_iconbg").addClass($scope.icon_bg);
				$("#acc_right_iconbg").addClass($scope.icon_bg);
			} else {
				$("#access_icon").attr("src", "assets/images/down.png");
				$("#collapseaccess").toggleClass('blackmenu', true);
				$("#access_title_bg").removeClass($scope.menu_class);
				$("#acc_left_iconbg").removeClass($scope.icon_bg);
				$("#acc_right_iconbg").removeClass($scope.icon_bg);

			}
		});


		/**
		 * toggleManager
		 */
		$scope.toggleManager={};

		/**
		 * system open and close
		 */
		$('#collapseOne').on('show.bs.collapse', function (data) {

			if('collapseOne' != data.target.id){
				return;
			}
		 	//ntp
		 	$scope.toggleManager.ntpInit();

			//syslog
			$scope.toggleManager.syslogInit();

			$scope.toggleManager.clusterInit();
		})

		$('#collapseOne').on('hidden.bs.collapse', function (data) {

			if('collapseOne' != data.target.id){
				return;
			}

		  	//ntp
		  	$scope.toggleManager.ntpDestory();
		})

		/**
		 * Wireless open and close
		 */		
		$('#collapseTwo').on('show.bs.collapse', function () {
			//rf
			$scope.toggleManager.rfInit();

			//rogue ap
			$scope.toggleManager.rogueApInit();

		 	//other
		 	$scope.toggleManager.otherInit();
		})


		/**
		 * Access open and close
		 */		
		$('#collapseFour').on('show.bs.collapse', function () {
		 	//access
			$scope.toggleManager.getauthinfo();
		 	$scope.toggleManager.aclGetRule();
		 	$scope.toggleManager.getBlackList();
        		$scope.toggleManager.getWhiteList();
        		$scope.toggleManager.getWallList();
		})

		/**
		 * [f_logout description]
		 */
		$scope.f_logout = function(){

			authentifiedRequest.post('/authentication/logout', null, null, function(data){
				// must return
				window.location.href = "/static/login.html";
			});
		}


		//open session time check


		document.onkeypress=banBackSpace;
		document.onkeydown=banBackSpace;
		function banBackSpace(e){
			var ev = e || window.event;
			var obj = ev.target || ev.srcElement;

			var t = obj.type || obj.getAttribute('type');

			var vReadOnly = obj.getAttribute('readonly');
			var vEnabled = obj.getAttribute('enabled');
			vReadOnly = (vReadOnly == null) ? false : vReadOnly;
			vEnabled = (vEnabled == null) ? true : vEnabled;

			var flag1=(ev.keyCode == 8 && (t=="password" || t=="text" || t=="textarea" || t=="number")
			&& (vReadOnly==true || vEnabled!=true))?true:false;

			var flag2=(ev.keyCode == 8 && t != "password" && t != "text" && t != "textarea" && t != "number")
				?true:false;

			if(flag2){
				return false;
			}
			if(flag1){
				return false;
			}
		}

	}]);