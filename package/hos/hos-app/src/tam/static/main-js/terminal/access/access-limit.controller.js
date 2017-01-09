angular.module("module.terminal.access",[])
    .controller('TerminalAccessController', ['$scope', '$translate', 'singleModal', 'authentifiedRequest', 'InterService', 'batchSyncConfig', 'FileUploader', 'toastr', 'hanCrypto', function($scope,$translate, singleModal, authentifiedRequest, InterService, batchSyncConfig, FileUploader, toastr, hanCrypto) {
        $scope.skin = InterService.skin;

        $scope.InterService = InterService;
        $scope.aps = InterService.getCanConfigAps();
        //var url_pro = "http://";
        var url_pro = InterService.getProtocol()+"://";
        //var url_port= ":8080";
        var url_port= ":"+InterService.getPort();

        $scope.$watch('InterService', function(newVal, oldVal) {
            if (newVal !== oldVal) {
                $scope.aps = InterService.getCanConfigAps();
            }
        }, true);

        $scope.BlackList = [];
        $scope.BlackListTemp = {"Begin_MAC":"", "End_MAC": ""};

        $scope.WhiteList = [];
        $scope.WhiteListTemp = {"Begin_MAC":"", "End_MAC": ""};

        $scope.WallList = [];
        $scope.WallListTemp = {"Begin_IP":"", "End_IP": ""};

        $scope.mac_compare = function(addedmac, obj, flag){
            var len = addedmac.length;
            //console.log(addedmac + obj.Begin_MAC);
            if(17 == len || flag <= 1){
                if(addedmac.toUpperCase() == obj.Begin_MAC.toUpperCase()){
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
                    if(obj.Begin_MAC >= $scope.arr[0] && obj.Begin_MAC <= $scope.arr[1]){
                        return true;
                    }  
                }
            }
            if(8 == len || flag <= 3){
                var newstr = obj.Begin_MAC.substr(0,8);
                if(addedmac.toUpperCase() == newstr.toUpperCase()){
                    return true;
                }
            }
            return false;
        }

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
        }
        /*
        * operate blacklist
        */
        $scope.toggleManager.getBlackList = function () {
            var params = {};
            authentifiedRequest.get("/getblacklist", params, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.BlackList = data.result;
                }
            },function(){
            })
        };

        $scope.Add_Blacklist = function(){
            
            if(null != $scope.BlackList){
                if($scope.BlackList.length >= 256){
                    // toastr.info('BlackList already pass 256!', '');
                    toastr.info($translate.instant("client_kick_user_1"), '');
                    return ;
                }
                var index = $scope.maclistFilterDuplicateObject($scope.BlackList, $scope.BlackListTemp);
                if(true == index){
                    /*toastr.info('The BlackList already add!', '');*/
                    toastr.info($translate.instant("access_add_blacklist_1"), '');
                    return ;
                }
            }
            /*var operatorMsg = 'Add Black list';*/
            var operatorMsg = 'access_add_blacklist_2';
            var requestParas = JSON.stringify($scope.BlackListTemp);
            batchSyncConfig.request("put", "/addBlacklist", null, requestParas, function(){
                $scope.toggleManager.getBlackList();
            },null, operatorMsg);
            $scope.BlackListTemp.Begin_MAC = "";
            $("form[name='add_black_mac']")[0].reset();
             this.add_black_mac.$setPristine();
            $scope.Cancel();
        };

        $scope.Del_Blacklist = function(blacklist){
            /*var operatorMsg = 'Delete black list';*/
            var operatorMsg = 'access_del_blacklist_1';
          /*  var confirm_tip = "Do you confirm to delete the IP address(" + blacklist + ")from the Blacklist?";*/
            var confirm_tip = $translate.instant("access_del_blacklist_2") + blacklist + "?";
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
                    if(result){
                        batchSyncConfig.request("delete", "/delBlacklist/" + blacklist, null, null, function(){
                            $scope.toggleManager.getBlackList();
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        batchSyncConfig.request("delete", "/delBlacklist/" + blacklist, null, null, function(){
            //            $scope.toggleManager.getBlackList();
            //        },null, operatorMsg);
            //    }
            //});
        };

        /**
         * mac Auth Account
         *
         */
        $scope.toggleManager.getWhiteList = function(){
            var params = {};
            authentifiedRequest.get("/getwhitelist", params, function(data, status){

                if(status == 200 && data != null && data.success){
                    $scope.WhiteList = data.result;
                }
            },function(){
            })
        };

        $scope.Add_Whitelist = function(){
            var operatorMsg = 'access_add_whitelist_1';
            if(null != $scope.WhiteList){
                if(8 == $scope.WhiteListTemp.Begin_MAC.length){
                    $scope.WhiteListTemp.End_MAC = "";
                }
                var index = $scope.maclistFilterDuplicateObject($scope.WhiteList, $scope.WhiteListTemp);
                if(true == index){
                    /*toastr.info('The white list already add or mac add overlap or begin mac greater than  end mac!', '');*/
                    toastr.info($translate.instant("access_add_whitelist_2"), '');
                    return ;
                }
            }
            var requestParas = JSON.stringify($scope.WhiteListTemp);
            batchSyncConfig.request("put", "/addwhitelist", null, requestParas, function(){
                $scope.toggleManager.getWhiteList();
            },null, operatorMsg);
            $scope.WhiteListTemp.Begin_MAC = "";
            $scope.WhiteListTemp.End_MAC = "";
            $("form[name='add_local_mac']")[0].reset();
            this.add_local_mac.$setPristine();
            $scope.Cancel();
        };

        $scope.Del_Whitelist = function(macaddr){
            var operatorMsg = 'access_del_whitelist_1';
            /*var confirm_tip = "Do you confirm to delete the whitelist mac(" + macaddr + ")?";*/
            var confirm_tip = $translate.instant("access_del_whitelist_2") + macaddr + "?";
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
                    if(result){
                        var url = "/delwhitelist/" + macaddr;
                        batchSyncConfig.request("delete", url, null, null, function(){
                            $scope.toggleManager.getWhiteList();
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        var url = "/delwhitelist/" + macaddr;
            //        batchSyncConfig.request("delete", url, null, null, function(){
            //            $scope.toggleManager.getWhiteList();
            //        },null, operatorMsg);
            //    }
            //});
        };

        /*
        * wall guardian list
        */
        $scope.ip2int = function(ip){
            var num = 0;
            ip = ip.split(".");
            num = Number(ip[0]) * 256 * 256 * 256 + Number(ip[1]) * 256 * 256 + Number(ip[2]) * 256 + Number(ip[3]);
            num = num >>> 0;
            return num;
        }

        $scope.ipaddr_compare = function(whitetemp){
            var iret = false;

            if("" == whitetemp.End_IP){
                return iret;
            }
            if(whitetemp.End_IP == whitetemp.Begin_IP){
                return iret;
            }

            var begin = $scope.ip2int(whitetemp.Begin_IP);
            var end = $scope.ip2int(whitetemp.End_IP);
            if(begin > end){
                iret = true;
                return iret;
            }

            return iret;
        }

        $scope.ip_range_compare = function(addedip, obj, flag){
            var ipflag = 0;
            var nowbegin = 0;
            var nowend = 0;
            var begin = 0;
            var end = 0;
            var iret = false;
            if(addedip.indexOf("-") > 0 ){
                ipflag = 1;
                $scope.added=addedip.split("-"); 
            }

            if(flag <= 1){
                if(0 == ipflag){
                    begin = $scope.ip2int(addedip);
                    nowbegin = $scope.ip2int(obj.Begin_IP);
                    if(begin == nowbegin){
                        iret = true;
                        return iret;
                    }
                }else{
                    begin = $scope.ip2int($scope.added[0]);
                    end = $scope.ip2int($scope.added[1]);
                    nowbegin = $scope.ip2int(obj.Begin_IP);
                    if((begin <= nowbegin) && (nowbegin <= end)){
                        iret = true;
                        return iret;
                    }
                }
            }
            if(ipflag == 1 && flag <= 2){
                begin = $scope.ip2int($scope.added[0]);
                end = $scope.ip2int($scope.added[1]);
                nowbegin = $scope.ip2int(obj.Begin_IP);
                nowend = $scope.ip2int(obj.End_IP);
                if(0 == nowend){
                    if(begin <= nowbegin && nowbegin <= end){
                        iret = true;
                        return iret;
                    }
                }else{
                    if((begin >= nowbegin) && (nowend >= begin)){
                        iret = true;
                        return iret;
                    }
                    if((begin <= nowbegin) && (nowend <= end)){
                        iret = true;
                        return iret;
                    } 
                    if((end >= nowbegin) && (nowend >= end)){
                        iret = true;
                        return iret;
                    }   
                }
            }
            return iret;
        }

        $scope.iplistFilterDuplicateObject = function(array, iptemp) {
            var temp = false;
            var tempobj = iptemp;
            var white = "";
            var flag = 0;
            if("" == tempobj.End_IP){
                flag = 1;
                white = tempobj.Begin_IP;
            }else {
                flag = 2;
                white = tempobj.Begin_IP + "-" + tempobj.End_IP;
            }

            //compare key and value
            $.each(array,function(i,val){
                var test = $scope.ip_range_compare(val.Domain, tempobj, flag);
                if(true == test){
                    temp = true;
                     return temp;
                }

                // if((val.Domain == white)){
                //     temp = true;
                //     return false;
                // }
            });
            
            return temp;
        }


        $scope.toggleManager.getWallList = function () {
            authentifiedRequest.get("/getwalllist", null, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.WallList = data.result;
                }
            },function(){
            })
        };

        $scope.Add_Walllist = function(){
            //var operatorMsg = 'Add walled garden list';
            var operatorMsg = 'access_walled_garden_4';
            if(null != $scope.WallList){
                if($scope.WallList.length >= 128){
                    /*toastr.info('wall already pass 128!', '');*/
                    toastr.info($translate.instant("access_walled_garden_1"), '');
                    return ;
                }
                
                var index = $scope.ipaddr_compare($scope.WallListTemp);
                if(true == index){
                    /*toastr.info('The beginip  greate than endip!', '');*/
                    toastr.info($translate.instant("access_walled_garden_2"), '');
                    return ;
                }

                var index = $scope.iplistFilterDuplicateObject($scope.WallList, $scope.WallListTemp);
                if(true == index){
                   /* toastr.info('The wall guardian  already add!', '');*/
                    toastr.info($translate.instant("access_walled_garden_3"), '');
                    return ;
                }
            }

            var requestParas = JSON.stringify($scope.WallListTemp);
            var params ={};
            batchSyncConfig.request("put", "/addwalllist", null, requestParas, function(){
                $scope.toggleManager.getWallList();
                $scope.WallListTemp.End_IP = "";
            },null, operatorMsg);

            $scope.WallListTemp.Begin_IP = "";
            $scope.WallListTemp.End_IP = "";
            $("form[name='add_whitelist']")[0].reset();
            this.add_whitelist.$setPristine();
            $scope.Cancel();
        };

        $scope.Del_Walllist = function(iplist){
            var operatorMsg = 'access_del_walled_garden_1';
            /*var confirm_tip = "Do you confirm to delete the IP address(" + iplist.Domain + ")from the IPaddress?";*/
            var confirm_tip = $translate.instant("access_del_walled_garden_2") + iplist.Domain + "?";
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
                    if(result){
                        batchSyncConfig.request("delete", "/delwalllist/" + iplist.Domain, null, null, function(){
                            $scope.toggleManager.getWallList();
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        batchSyncConfig.request("delete", "/delwalllist/" + iplist.Domain, null, null, function(){
            //            $scope.toggleManager.getWallList();
            //        },null, operatorMsg);
            //    }
            //});
        };

        $scope.Cancel= function(){

        };

        $scope.CheckStartingMac = function(){
            if($scope.WhiteListTemp.Begin_MAC!=null || $scope.WhiteListTemp.Begin_MAC != ""){
                var len = $scope.WhiteListTemp.Begin_MAC.length;
                if(len == 8){
                    $scope.WhiteListTemp.End_MAC = "";
                }
            }
        };

        // $scope.getBlackList();
        // $scope.getWhiteList();
        // $scope.getWallList();
        //$scope.toggleManager.getBlackList();
        //$scope.toggleManager.getWhiteList();
        //$scope.toggleManager.getWallList();
    }])
;
