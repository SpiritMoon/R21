/**
 * Created by shensf on 2016/3/25.
 */
angular.module("module.client")
    .controller('ClientDetailController',['$scope', '$modalInstance','$translate','authentifiedRequest', 'InterService', 'batchSyncConfig', 'clientService', 'toastr', 
	function($scope, $modalInstance,$translate,authentifiedRequest, InterService, batchSyncConfig, clientService,toastr) {
      
        /**
         * clientDetailGroupList页面参数对象初始化
         */
        $scope.skin = InterService.skin;
        $scope.clientDetailGroupList = [];
        $scope.allClientGroupList = $scope.clientDetailGroupList;
        $scope.currentDetailTemp = {
            "Name":"",
            "IP":"",
            "UserMAC":"",
            "WLAN":"",
            "AP":"",
            "APName":"",
            "APInfo":"",
            "Auth":"",
            "FREQ":"",
            "OnlineTime":"",
            "SessionTime":"",
            "RSSI":0,
            "MODE":"",
            "RXRATE":0,
            "TXRATE":0,
            "UPRATE":0,
            "DOWNRATE":0,
            "InputFlow":0,
            "OutputFlow":0,
            "TerminalType":"",
            "FingerPrint":""
        };
        $scope.isShowDetails = true;
        $scope.searchVisible = false;
        $scope.search = {
            target: ""
        };

        $scope.showSearch = function(){
            $scope.searchVisible = !$scope.searchVisible;
        };

        /**
         **获取当前行client详细信息
         **/
        // $scope.currentLine = 0;//记录上次点击的行号
        $scope.getCurrentClientDetail = function(currentDetail){
            // $scope.isShowDetails = true;
            // var index = (currentDetail.Id - 1) % 10;
            // if(index == $scope.currentLine) {
            //     return;
            // }
            // $scope.currentLine = index;

            $scope.currentDetailTemp=currentDetail;
        };

        // $scope.Temp = {
        //     "mac":"",
        //     "ap":"",
        //     "ip":"",
        //     "uptime":"",
        //     "livetime":"",
        //     "devtype":"",
        //     "hostname":"",
        //     "ostype":"",
        // };

        // $scope.serarchClient = function(){
        //     var params = {};
        //     authentifiedRequest.get("/searchsta", params, function(data){
        //         if(data.success){
        //             for (var a in data) {
        //                   for (var b in data[a]) {
        //                        alert(data[a]);
        //                   }
        //             }
        //             console.info('serarch userlist success!');
        //         }else{
        //             console.info('serarch userlist fail!');
        //         }
        //     },function(){
        //         console.info('serarch userlist error!');
        //     })
        // };

        // $scope.myClass = 'red';
        // $scope.isClick = 'No!';
        // $scope.myKeyup = function(e){
        //     var keycode = window.event?e.keyCode:e.which;
        //     if(keycode == 13){
        //         //$scope.serarchClient();
        //     }
        // };

        $scope.deleteuser = function(userinfo){
            var len = $scope.clientDetailGroupList.length;
            for(var i = 0; i < len; i++){
                if($scope.clientDetailGroupList[i].UserMAC == userinfo.UserMAC){
                    $scope.clientDetailGroupList.splice(i, 1);
                    break;
                }
            }
        }
        $scope.BlackList = [];
        $scope.getBlackList = function () {
            var params = {};
            authentifiedRequest.get("/getblacklist", params, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.BlackList = data.result;
                }
            },function(){
            })
        };
        $scope.getBlackList();
		$scope.mac_compare = function(addedmac, obj, flag){
            var len = addedmac.length;
            console.log(addedmac + obj.Begin_MAC);
            if(17 == len || flag <= 1){
                if(addedmac == obj.Begin_MAC){
                    return true;
                }
            }
            if(35 == len || flag <= 2){
                $scope.arr=addedmac.split("-"); 
                    if(obj.End_MAC != ""){
                    if(obj.Begin_MAC <= $scope.arr[0] && obj.End_MAC >= $scope.arr[0]){
                        return true;
                    }
                    if(obj.Begin_MAC >= $scope.arr[0] && obj.End_MAC <= $scope.arr[1]){
                        return true;
                    }
                    if(obj.Begin_MAC <= $scope.arr[1] && obj.End_MAC >= $scope.arr[1]){
                        return true;
                    } 
                }else {
                    if(obj.Begin_MAC >= $scope.arr[1] && obj.Begin_MAC <= $scope.arr[1]){
                        return true;
                    } 
                }
            }
            if(8 == len || flag <= 3){
                var newstr = obj.Begin_MAC.substr(0,8);
                if(addedmac == newstr){
                    return true;
                }
            }
            return false;
        };
		$scope.maclistFilterDuplicateObject = function(array, acltemp) {
            var temp = false;
            var tempobj = acltemp;
            var macaddr = "";
            var flag = 0;
            if("" == tempobj.End_MAC){
                if(8 == tempobj.Begin_MAC.length){
                    flag = 3;
                }else{
                    flag = 1;
                }
                macaddr = tempobj.Begin_MAC;
            }else {
                flag = 2;
                var beginstr = tempobj.Begin_MAC.substr(0,8);
                var endstr = tempobj.End_MAC.substr(0,8);
                if(beginstr != endstr || tempobj.Begin_MAC > tempobj.End_MAC){
                    return true;
                }
                macaddr = tempobj.Begin_MAC + "-" + tempobj.End_MAC;
            }

            //compare key and value
            $.each(array,function(i,val){
                var test = $scope.mac_compare(val.MAC, tempobj, flag);
                if(true == test){
                    temp = true;
                     return temp;
                }
            });
            return temp;
        };
        $scope.kickuser = function(userinfo){
            var confirm_tip=  $translate.instant("kickOutUser1")+ userinfo.UserMAC +$translate.instant("kickOutUser2");
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: confirm_tip,
                callback: function(result) {
                    if(result) {

                        //add to blacklist
                        if($scope.BlackList.length >= 256){
                            toastr.info($translate.instant("client_kick_user_1"), '');
                        }else{
                            $scope.BlackListTemp = {"Begin_MAC":userinfo.UserMAC, "End_MAC": ""};
                            var index = $scope.maclistFilterDuplicateObject($scope.BlackList, $scope.BlackListTemp);
                            if(true == index){
                                toastr.info($translate.instant("access_add_blacklist_1"), '');
                            }else{
                                var operatorMsg = 'access_add_blacklist_3';
                                var requestParas2 = JSON.stringify($scope.BlackListTemp);
                                batchSyncConfig.request("put", "/addBlacklist", null, requestParas2, function(){
                                    //kickoff user
                                    $scope.deleteuser(userinfo);
                                    $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
                                    if(!$scope.currentDetailTemp){
                                        $scope.isShowDetails = false;
                                    }
                                    var requestParas = JSON.stringify(userinfo);
                                    batchSyncConfig.request("put", "/kickuser", null, requestParas, function(){},null, "client_kick_user_2");

                                },null, operatorMsg);
                                return;
                            }
                        }

                        //kickoff user
                        $scope.deleteuser(userinfo);
                        $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
                        if(!$scope.currentDetailTemp){
                            $scope.isShowDetails = false;
                        }
                        var requestParas = JSON.stringify(userinfo);
                        batchSyncConfig.request("put", "/kickuser", null, requestParas, function(){},null, "client_kick_user_2");
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
				//	//add to blacklist
				//	if($scope.BlackList.length >= 256){
            //            toastr.info($translate.instant("client_kick_user_1"), '');
            //        }else{
				//		$scope.BlackListTemp = {"Begin_MAC":userinfo.UserMAC, "End_MAC": ""};
				//		var index = $scope.maclistFilterDuplicateObject($scope.BlackList, $scope.BlackListTemp);
				//		if(true == index){
				//			toastr.info($translate.instant("access_add_blacklist_1"), '');
				//		}else{
				//			var operatorMsg = 'access_add_blacklist_3';
				//			var requestParas2 = JSON.stringify($scope.BlackListTemp);
				//			batchSyncConfig.request("put", "/addBlacklist", null, requestParas2, function(){
            //                    //kickoff user
            //                    $scope.deleteuser(userinfo);
            //                    $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
            //                    if(!$scope.currentDetailTemp){
            //                        $scope.isShowDetails = false;
            //                    }
            //                    var requestParas = JSON.stringify(userinfo);
            //                    batchSyncConfig.request("put", "/kickuser", null, requestParas, function(){},null, "client_kick_user_2");
            //
            //                },null, operatorMsg);
            //                return;
				//		}
				//	}
				//
				//	//kickoff user
				//	$scope.deleteuser(userinfo);
            //        $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
            //        if(!$scope.currentDetailTemp){
            //            $scope.isShowDetails = false;
            //        }
		     //       var requestParas = JSON.stringify(userinfo);
            //        batchSyncConfig.request("put", "/kickuser", null, requestParas, function(){},null, "client_kick_user_2");
            //    }
            //});


        };
        $scope.kickoffuser = function (userinfo) {
            var confirm_tip=  $translate.instant("kickOffUser")+ userinfo.UserMAC +" ?";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: confirm_tip,
                callback: function(result) {
                    if(result) {
                        $scope.deleteuser(userinfo);
                        $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
                        if(!$scope.currentDetailTemp){
                            $scope.isShowDetails = false;
                        }
                        var requestParas = JSON.stringify(userinfo);
                        batchSyncConfig.request("put", "/kickuser", null, requestParas, function(){},null, "client_kick_user_2");
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        $scope.deleteuser(userinfo);
            //        $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
            //        if(!$scope.currentDetailTemp){
            //            $scope.isShowDetails = false;
            //        }
            //        var requestParas = JSON.stringify(userinfo);
            //        batchSyncConfig.request("put", "/kickuser", null, requestParas, function(){},null, "client_kick_user_2");
            //    }
            //});
        };

        $scope.selectRow = function (tr1){
            var   curRow;
            var   curRowId;
            var   curColor;
            if(curRow)
            {
                curRow.bgColor=curColor;
                curColor=tr1.bgColor;
                tr1.bgColor="#FFE9B3";
            }else{
                curColor=tr1.bgColor;
                tr1.bgColor="#FFE9B3";
            }
            curRow=tr1;
            curRowId=tr1.id;
        }

        /**
         *
         */
        $scope.ok = function() {
            $modalInstance.close();
        };

        $scope.cancel = function() {
            $modalInstance.close();
        };

        /*
        *get total list
        */
        $scope.init = function(){
            $scope.clientDetailGroupList = [];
            $scope.clientService = clientService;
            $scope.clientDetailGroupList = $scope.clientService.getClientList();
            for(var i =0 ;i<$scope.clientDetailGroupList.length; i++){
                var deviceType = $scope.clientDetailGroupList[i].FingerPrint;
                if(deviceType.indexOf("\\")>0){//include double \\
                    deviceType = deviceType.replace("\\"," ");
                    $scope.clientDetailGroupList[i].FingerPrint = deviceType;
                }
            }
            $scope.allClientGroupList = $scope.clientDetailGroupList;

            $scope.currentDetailTemp = $scope.clientDetailGroupList[0];
            if(!$scope.currentDetailTemp){
                $scope.isShowDetails = false;
            }

        };
        $scope.searchClient = function(){
            $scope.newClientGroupList = [];
            if($scope.search.target){
                var len = $scope.allClientGroupList.length;
                var IPFlag;
                var MACFlag;
                var NameFlag;
                for(var i = 0; i < len; i++){
                    IPFlag = !$scope.allClientGroupList[i].IP.indexOf($scope.search.target);
                    MACFlag =  !$scope.allClientGroupList[i].UserMAC.toUpperCase().indexOf($scope.search.target.toUpperCase());
                    NameFlag = !$scope.allClientGroupList[i].Name.toUpperCase().indexOf($scope.search.target.toUpperCase());
                   /* if( IPFlag|| nameFlag){*/
                    if( IPFlag|| NameFlag || MACFlag){
                        $scope.newClientGroupList.push($scope.allClientGroupList[i]);
                    }
                }
                $scope.clientDetailGroupList = $scope.newClientGroupList;
            }else{
                $scope.clientDetailGroupList = $scope.allClientGroupList;
            }
        };

        //$scope.$watch('clientService', function(newVal, oldVal) {
        //    if (newVal !== oldVal) {
        //        $scope.clientDetailGroupList = $scope.clientService.getClientList();
        //    }
        //}, true);

        $scope.init();
    }])
;