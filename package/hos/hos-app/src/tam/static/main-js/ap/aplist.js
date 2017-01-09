angular.module('module.ap.apinfo')
    .controller('APinfoController', ['$rootScope','$scope','$modalInstance','$translate','authentifiedRequest','InterService','batchSyncConfig','FileUploader','lockScreen','$http','ClusterService', 'toastr', 'operationLog','$interval', 'APService', function($rootScope,$scope,$modalInstance,$translate,authentifiedRequest,InterService,batchSyncConfig,FileUploader,lockScreen,$http,ClusterService,toastr,operationLog,$interval, APService) {
	    $scope.skin = InterService.skin;
        var url_pro = InterService.getProtocol()+"://";
        //var url_pro = "http://";
        var url_port= ":"+InterService.getPort();
        //var url_port= ":8080";
        $scope.aplistinfo={};
        $scope.uploadflag={'connect':false, 'num':0, 'mac':'', 'byurlflag':false};
        $scope.select={"selectall":false};
        $scope.aplistdetailinfo={"PVC":[],"SVC":[],"MEM":[],"working":[],"joining":[]};
        /****
         * isEditApname:ap name whether in modified state
         * showdhcp￡oip address whether in modified state
         * isEditip:ip address is in static modified state or dhcp modified state
         * apinfoshow:ap state is working or joining .if working, ap normal display.if joining,ap only show status
         * upload2one:upload verion to one or to all
         */
        $scope.flag={"isEditApname":false,"isEditip":false,"showdhcp":true,"apinfoshow":true,"upload2one":true,"noeditloc":true};
        $scope.tabflag={"detailtab":true,"cfgtab":false,"updatetab":false,"restoretab":false};
        $scope.edit = {"apNewName":"","mac":"","proto":"","ipaddr":"","netmask":"","gateway":""};
        $scope.editloc = {"aploc":""};
        $scope.byurl  ={"url":""};
        $scope.currentApInfo = {};
        $scope.apInfo = {};
        $scope.InterService = InterService;
        $scope.iSurlorloc="false";
        $scope.timer=null;
        $scope.roottimer = null;

        /*******************left function start**************************/
        lockScreen.lock();
       var FirstgetAPList = function (){
            if($scope.timer != null){
                $interval.cancel($scope.timer);
            }
            $scope.aplistdetailinfo={"PVC":[],"SVC":[],"MEM":[],"working":[],"joining":[]};
            APService.HttpGetApListInfo(function(){
                getCurrentApInfo();
                getaplistdetailinfo();
                $scope.clusterInfo = ClusterService.getClusterinfoSer();
                $scope.$emit("to-aplist-parent", true);
            });
        }

        var setOutTime2Login = function(){
            $scope.$emit('modal-to-main',"cancelTimer");
            var timerDemo = $interval(function() {
                lockScreen.lock(60000);
                authentifiedRequest.get("/checkstate", null, function(response){
                    if(response != null && response.success){
                        lockScreen.unlock();
                        window.location.href = "login.html";
                    }
                }, function(){  });
            }, 30 * 1000);
            $scope.roottimer = timerDemo;
        }

        FirstgetAPList();

       var getCurrentApInfo = function(){
            authentifiedRequest.get("/getapname", null, function(response){
                if(response != null && response.success){
                    $scope.uploadflag.mac = response.result.mac;
                }else{
                    $scope.uploadflag.mac = "";
                }
            }, function(){
                $scope.uploadflag.mac = "";
            });         
        }

        $scope.funDetailInfo = function (item) {
            $scope.currentApInfo = item;
            $scope.flag.upload2one=true;
            $scope.tabflag={"detailtab":true,"cfgtab":false,"updatetab":false,"restoretab":false};
            $scope.flag={"isEditApname":false,"isEditip":false,"showdhcp":true,"apinfoshow":true,"upload2one":true,"noeditloc":true};
            if((item.state==4)||(item.state==1)){
                $scope.flag.apinfoshow=false;
                toastr.warning($translate.instant("apinfoShow"));
                return;
            }
            $scope.apInfo = {};
            $scope.flag.showdhcp=true;
            $scope.flag.apinfoshow=true;
            var url = url_pro + item.ip + url_port+"/baseinfo";
            lockScreen.lock();
            authentifiedRequest.get(url, null, function(response){
                if(response != null && response.success){
                    $scope.apInfo=response.result;
                    lockScreen.unlock();
                }else{
                    lockScreen.unlock();
                    toastr.warning($translate.instant("getinfoApF"));
                }
            }, function(){
                lockScreen.unlock();
                toastr.warning($translate.instant("getinfoApF"));
            });
        };
        /***uploadFaseFlag
        ***100:have no flag
        ***101:upload failed
        ***102:upload success
        **/
        function getaplistdetailinfo(){
            $scope.aplistinfo=InterService.getApListInfo();
            $scope.aplistdetailinfo.working=InterService.getCanConfigAps();
            var pvc= 0, member= 0, svc= 0, join=0;

            for(var j=0; j<$scope.aplistinfo.length; j++){
                if(($scope.aplistinfo[j].role==3)&&($scope.aplistinfo[j].state!=1)){
                    $scope.aplistdetailinfo.MEM[member]=$scope.aplistinfo[j];
                    $scope.aplistdetailinfo.MEM[member].uploadFaseFlag = 100;
                    member++;
                }else if($scope.aplistinfo[j].role==1){
                    $scope.aplistdetailinfo.PVC[pvc] =  $scope.aplistinfo[j];
                    $scope.aplistdetailinfo.PVC[pvc].uploadFaseFlag = 100;
                    $scope.funDetailInfo($scope.aplistinfo[j]);
                    pvc++;
                }else if(($scope.aplistinfo[j].role==2)&&($scope.aplistinfo[j].state!=1)){
                    $scope.aplistdetailinfo.SVC[svc]=$scope.aplistinfo[j];
                    $scope.aplistdetailinfo.SVC[svc].uploadFaseFlag = 100;
                    svc++;
                }
                if($scope.aplistinfo[j].state==1){
                    $scope.aplistdetailinfo.joining[join]=$scope.aplistinfo[j];
                    join++;
                }
            }
        };

        $scope.funcfg = function (item) {
            $scope.currentApInfo = item;
            $scope.flag.upload2one=true;
            $scope.cfgtext={"content":""};
            $scope.tabflag={"detailtab":false,"cfgtab":true,"updatetab":false,"restoretab":false};
            var url = url_pro + item.ip + url_port+"/currentcfg";
            lockScreen.lock();
            authentifiedRequest.get(url, null, function(response){
                if(response != null && response.success){
                    $scope.cfgtext.content=response.result;
                    lockScreen.unlock();
                }else{
                    lockScreen.unlock();
                    toastr.warning($translate.instant("getconfigureApF"));
                }
            }, function(){
                lockScreen.unlock();
                toastr.warning($translate.instant("getconfigureApF"));
            });
        }

        $scope.showRestore = function () {
            $scope.flag.upload2one=true;
            $scope.tabflag={"detailtab":false,"cfgtab":false,"updatetab":false,"restoretab":true};
        }

        $scope.funupdate = function (item) {
            $scope.flag.upload2one=true;
            $scope.currentApInfo = item;
            $scope.tabflag={"detailtab":false,"cfgtab":false,"updatetab":true,"restoretab":false};
        }

        $scope.showbashupload = function () {
            $scope.flag.upload2one=false;
            $scope.tabflag={"detailtab":false,"cfgtab":false,"updatetab":true,"restoretab":false};
        }

        $scope.reboot = function(item){
            $scope.flag.upload2one=true;
            var url = url_pro + item.ip + url_port+"/reboot";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("rebootAp"),
                callback: function(result) {
                    if(result) {
                        var operatorMsg = "reboot_ap_log_name";
                        var loginfo = [{
                            'ip':item.ip,
                            'success':"module_operate_failure",
                            'msg':''}];
                        lockScreen.lock(60000);
                        authentifiedRequest.put(url, null, null, function(response){
                            if(response != null && response.success){
                                loginfo[0].success = "module_operate_success";
                                loginfo[0].msg = 'ap_log_success';
                                if(item.mac.toUpperCase() == $scope.uploadflag.mac.toUpperCase()){
                                    setOutTime2Login();
                                }else{
                                    lockScreen.unlock();
                                }
                                toastr.warning( $translate.instant("rebootApS"));
                            }else{
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = 'ap_log_error_1';
                                toastr.warning( $translate.instant("rebootApF"));
                                lockScreen.unlock();
                            }
                            operationLog.setLog(operatorMsg, loginfo, null);

                        }, function(){
                            loginfo[0].success = "module_operate_failure";
                            loginfo[0].msg = 'failedServer';
                            operationLog.setLog(operatorMsg, loginfo, null);
                            toastr.warning($translate.instant("failedServer"));
                            lockScreen.unlock();
                        });
                    }
                }
            });
            //bootbox.confirm($translate.instant("rebootAp"), function(result) {
            //    if(result) {
            //        var operatorMsg = "reboot_ap_log_name";
            //        var loginfo = [{
            //            'ip':item.ip,
            //            'success':"module_operate_failure",
            //            'msg':''}];
            //        lockScreen.lock(60000);
            //        authentifiedRequest.put(url, null, null, function(response){
            //            if(response != null && response.success){
            //                loginfo[0].success = "module_operate_success";
            //                loginfo[0].msg = 'ap_log_success';
            //                if(item.mac.toUpperCase() == $scope.uploadflag.mac.toUpperCase()){
            //                    setOutTime2Login();
            //                }else{
            //                    lockScreen.unlock();
            //                }
            //                toastr.warning( $translate.instant("rebootApS"));
            //            }else{
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = 'ap_log_error_1';
            //                toastr.warning( $translate.instant("rebootApF"));
            //                lockScreen.unlock();
            //            }
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //
            //        }, function(){
            //            loginfo[0].success = "module_operate_failure";
            //            loginfo[0].msg = 'failedServer';
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //            toastr.warning($translate.instant("failedServer"));
            //            lockScreen.unlock();
            //        });
            //    }
            //});
        }

        /*******************left function end**************************/
        /*******************right function start**************************/

        $scope.saveOrCancelApName = function(type){
            if(type==100){
                $scope.edit = {"apNewName":"","mac":"","proto":"","ipaddr":"","netmask":"","gateway":""};
                $scope.flag.isEditApname = !$scope.flag.isEditApname;
            }else if(type==101){
                var url = url_pro + $scope.currentApInfo.ip + url_port+"/chgapname";
                var bodyParas={"mac":$scope.currentApInfo.mac,"apname":$scope.edit.apNewName};
                var operatorMsg = "modify_apName_log_name";
                var loginfo = [{
                    'ip':$scope.currentApInfo.ip,
                    'success':"module_operate_failure",
                    'msg':''}];
                lockScreen.lock();
                authentifiedRequest.put(url, null, bodyParas, function(response){
                    if(response != null && response.success){
                        $scope.apInfo.apName = $scope.edit.apNewName;
                        $scope.flag.isEditApname = !$scope.flag.isEditApname;
                        var mac=$scope.currentApInfo.mac.toUpperCase();
                        if($scope.currentApInfo.role==1){
                            $scope.aplistdetailinfo.PVC[0].apname = $scope.edit.apNewName;
                        }else if($scope.currentApInfo.role==2){
                            for(var i=0; i<$scope.aplistdetailinfo.SVC.length; i++){
                                var des_mac = $scope.aplistdetailinfo.SVC[i].mac.toUpperCase();
                                if(mac==des_mac){
                                    $scope.aplistdetailinfo.SVC[i].apname = $scope.edit.apNewName;
                                    break;
                                }
                            }
                        }else if($scope.currentApInfo.role==3){
                            for(var i=0; i<$scope.aplistdetailinfo.MEM.length; i++){
                                var des_mac = $scope.aplistdetailinfo.MEM[i].mac.toUpperCase();
                                if(mac==des_mac){
                                    $scope.aplistdetailinfo.MEM[i].apname = $scope.edit.apNewName;
                                    break;
                                }
                            }
                        }

                        loginfo[0].success = "module_operate_success";
                        loginfo[0].msg = "ap_log_success";
                        lockScreen.unlock();
                    }else{
                        lockScreen.unlock();
                        toastr.warning($translate.instant("setNameApF"));
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = "ap_log_error_1";
                    }
                    operationLog.setLog(operatorMsg, loginfo, null);
                }, function(){
                    lockScreen.unlock();
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = "failedServer";
                    operationLog.setLog(operatorMsg, loginfo, null);
                    toastr.warning($translate.instant("failedServer"));
                });
            }else if(type==102){
                $scope.flag.isEditApname = !$scope.flag.isEditApname;
                $scope.edit.apNewName = "";
            }
        }

        $scope.acceptAp = function(){
            var bodyParas={"mac":$scope.currentApInfo.mac};
            var cluster_num = $scope.aplistinfo.length - $scope.aplistdetailinfo.joining.length;
            if(cluster_num <16){
                bootbox.confirm({
                    buttons: {
                        cancel: {
                            label: $translate.instant("Cancel")
                        },
                        confirm: {
                            label: $translate.instant("OK")
                        }
                    },
                    message: $translate.instant("joingAp"),
                    callback: function(result) {
                        if(result) {
                            lockScreen.lock();
                            var url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/toauth";
                            var operatorMsg = "ap_access_group_name";
                            var loginfo = [{
                                'ip':$scope.currentApInfo.ip,
                                'success':"module_operate_failure",
                                'msg':''}];
                            authentifiedRequest.put(url, null,bodyParas, function(response){
                                if(response != null && response.success){
                                    toastr.info($translate.instant("successfullyAp"), '');
                                    loginfo[0].success = "module_operate_success";
                                    loginfo[0].msg = "ap_log_success";
                                }else{
                                    toastr.warning($translate.instant("failedAp"), '');
                                    loginfo[0].success = "module_operate_failure";
                                    loginfo[0].msg = "ap_log_error_1";
                                }
                                operationLog.setLog(operatorMsg, loginfo, null);
                                var timerDemo = $interval(function() {
                                    FirstgetAPList()
                                }, 3 * 1000);
                                $scope.timer = timerDemo;
                            }, function(){
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = "failedServer";
                                operationLog.setLog(operatorMsg, loginfo, null);
                                toastr.warning($translate.instant("failedServer"));
                                lockScreen.unlock();
                            });
                        }
                    }
                });
                //bootbox.confirm($translate.instant("joingAp"), function(result) {
                //    if(result) {
                //        lockScreen.lock();
                //        var url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/toauth";
                //        var operatorMsg = "ap_access_group_name";
                //        var loginfo = [{
                //            'ip':$scope.currentApInfo.ip,
                //            'success':"module_operate_failure",
                //            'msg':''}];
                //        authentifiedRequest.put(url, null,bodyParas, function(response){
                //            if(response != null && response.success){
                //                toastr.info($translate.instant("successfullyAp"), '');
                //                loginfo[0].success = "module_operate_success";
                //                loginfo[0].msg = "ap_log_success";
                //            }else{
                //                toastr.warning($translate.instant("failedAp"), '');
                //                loginfo[0].success = "module_operate_failure";
                //                loginfo[0].msg = "ap_log_error_1";
                //            }
                //            operationLog.setLog(operatorMsg, loginfo, null);
                //            var timerDemo = $interval(function() {
                //                FirstgetAPList()
                //            }, 3 * 1000);
                //            $scope.timer = timerDemo;
                //        }, function(){
                //            loginfo[0].success = "module_operate_failure";
                //            loginfo[0].msg = "failedServer";
                //            operationLog.setLog(operatorMsg, loginfo, null);
                //            toastr.warning($translate.instant("failedServer"));
                //            lockScreen.unlock();
                //        });
                //    }
                //});
            }else{
                toastr.warning($translate.instant("apgroupFull"), '');
            }
        };

        $scope.kickOffAp = function(){
            var bodyParas={"mac":$scope.currentApInfo.mac};
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("kickOffAp"),
                callback: function(result) {
                    if(result) {
                        lockScreen.lock();
                        var url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/kickoffap";
                        var operatorMsg = "kick_ap_log_name";
                        var loginfo = [{
                            'ip':$scope.currentApInfo.ip,
                            'success':"module_operate_failure",
                            'msg':''}];
                        authentifiedRequest.put(url, null,bodyParas, function(response){
                            if(response != null && response.success){
                                toastr.info($translate.instant("kickOffApS"), '');
                                loginfo[0].success = "module_operate_success";
                                loginfo[0].msg = "ap_log_success";
                            }else{
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = "ap_log_error_1";
                                toastr.warning($translate.instant("kickOffApF"), '');
                            }
                            operationLog.setLog(operatorMsg, loginfo, null);
                            var timerDemo = $interval(function() {
                                FirstgetAPList()
                            }, 3 * 1000);
                            $scope.timer = timerDemo;
                        }, function(){
                            loginfo[0].success = "module_operate_failure";
                            loginfo[0].msg = 'failedServer';
                            operationLog.setLog(operatorMsg, loginfo, null);
                            toastr.warning($translate.instant("failedServer"));
                            lockScreen.unlock();
                        });
                    }
                }
            });
            //bootbox.confirm($translate.instant("kickOffAp"), function(result) {
            //    if(result) {
            //        lockScreen.lock();
            //        var url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/kickoffap";
            //        var operatorMsg = "kick_ap_log_name";
            //        var loginfo = [{
            //            'ip':$scope.currentApInfo.ip,
            //            'success':"module_operate_failure",
            //            'msg':''}];
            //        authentifiedRequest.put(url, null,bodyParas, function(response){
            //            if(response != null && response.success){
            //                toastr.info($translate.instant("kickOffApS"), '');
            //                loginfo[0].success = "module_operate_success";
            //                loginfo[0].msg = "ap_log_success";
            //            }else{
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = "ap_log_error_1";
            //                toastr.warning($translate.instant("kickOffApF"), '');
            //            }
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //            var timerDemo = $interval(function() {
            //                FirstgetAPList()
            //            }, 3 * 1000);
            //            $scope.timer = timerDemo;
            //        }, function(){
            //            loginfo[0].success = "module_operate_failure";
            //            loginfo[0].msg = 'failedServer';
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //            toastr.warning($translate.instant("failedServer"));
            //            lockScreen.unlock();
            //        });
            //    }
            //});
        }

        $scope.deleteAp = function(){
            var bodyParas={"mac":$scope.currentApInfo.mac};
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("delAp"),
                callback: function(result) {
                    if(result) {
                        lockScreen.lock();
                        var url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/deleteap";
                        var operatorMsg = "delete_ap_log_name";
                        var loginfo = [{
                            'ip':$scope.currentApInfo.ip,
                            'success':"module_operate_failure",
                            'msg':''}];
                        authentifiedRequest.put(url, null,bodyParas, function(response){
                            if(response != null && response.success){
                                toastr.info($translate.instant("delApS"), '');
                                loginfo[0].success = "module_operate_success";
                                loginfo[0].msg = "ap_log_success";
                            }else{
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = "ap_log_error_1";
                                toastr.warning($translate.instant("delApF"), '');
                            }
                            operationLog.setLog(operatorMsg, loginfo, null);
                            var timerDemo = $interval(function() {
                                FirstgetAPList()
                            }, 3 * 1000);
                            $scope.timer = timerDemo;
                        }, function(){
                            loginfo[0].success = "module_operate_failure";
                            loginfo[0].msg = 'failedServer';
                            operationLog.setLog(operatorMsg, loginfo, null);
                            toastr.warning($translate.instant("failedServer"));
                            lockScreen.unlock();
                        });
                    }
                }
            });
            //bootbox.confirm($translate.instant("delAp"), function(result) {
            //    if(result) {
            //        lockScreen.lock();
            //        var url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/deleteap";
            //        var operatorMsg = "delete_ap_log_name";
            //        var loginfo = [{
            //            'ip':$scope.currentApInfo.ip,
            //            'success':"module_operate_failure",
            //            'msg':''}];
            //        authentifiedRequest.put(url, null,bodyParas, function(response){
            //            if(response != null && response.success){
            //                toastr.info($translate.instant("delApS"), '');
            //                loginfo[0].success = "module_operate_success";
            //                loginfo[0].msg = "ap_log_success";
            //            }else{
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = "ap_log_error_1";
            //                toastr.warning($translate.instant("delApF"), '');
            //            }
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //            var timerDemo = $interval(function() {
            //                FirstgetAPList()
            //            }, 3 * 1000);
            //            $scope.timer = timerDemo;
            //        }, function(){
            //            loginfo[0].success = "module_operate_failure";
            //            loginfo[0].msg = 'failedServer';
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //            toastr.warning($translate.instant("failedServer"));
            //            lockScreen.unlock();
            //        });
            //    }
            //});
        }

        $scope.Update2PVC = function(){
            var bodyParas={"mac":$scope.currentApInfo.mac};
            var url = url_pro + $scope.currentApInfo.ip + url_port+"/prioritychange";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("apToPvc"),
                callback: function(result) {
                    if(result) {
                        lockScreen.lock();
                        var operatorMsg = "update2pvc_log_name";
                        var loginfo = [{
                            'ip':$scope.currentApInfo.ip,
                            'success':"module_operate_failure",
                            'msg':''}];
                        var operatorMsg1 = "update2vc_log_name";
                        var loginfo1 = [{
                            'ip':"PVC",
                            'success':"module_operate_failure",
                            'msg':''}];
                        authentifiedRequest.put(url, null, bodyParas, function(response){
                            if(response != null && response.success){
                                loginfo[0].success = "module_operate_success";
                                loginfo[0].msg = "ap_log_success";
                                //var bodyParas={"mac":$scope.aplistdetailinfo.PVC[0].mac,"role":0};
                                var pvc_url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/prioritychange";
                                authentifiedRequest.put(pvc_url, null, bodyParas, function(response){
                                    if(response != null && response.success){
                                        toastr.info($translate.instant("changeRoleS"), '');
                                        loginfo1[0].success = "module_operate_success";
                                        loginfo1[0].msg = "ap_log_success";
                                        var operatorBashMsg = "restart_ap_cluster_log_name";
                                        batchSyncConfig.request("put","/reloadclt",null, null, null, null,operatorBashMsg);
                                        lockScreen.unlock();
                                    }else{
                                        loginfo1[0].success = "module_operate_failure";
                                        loginfo1[0].msg = "ap_log_error_1";
                                        toastr.warning($translate.instant("changeRoleF"), '');
                                        lockScreen.unlock();
                                    }
                                    operationLog.setLog(operatorMsg1, loginfo1, null);
                                }, function(){
                                    loginfo1[0].success = "module_operate_failure";
                                    loginfo1[0].msg = 'failedServer';
                                    operationLog.setLog(operatorMsg1, loginfo1, null);
                                    toastr.warning($translate.instant("failedServer"));
                                    lockScreen.unlock();
                                })
                            }else{
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = "ap_log_error_1";
                                toastr.warning($translate.instant("changeRoleF"), '');
                                lockScreen.unlock();
                            }
                            operationLog.setLog(operatorMsg, loginfo, null);
                        }, function(){
                            loginfo[0].success = "module_operate_failure";
                            loginfo[0].msg = 'failedServer';
                            operationLog.setLog(operatorMsg, loginfo, null);
                            toastr.warning($translate.instant("failedServer"));
                            lockScreen.unlock();
                        });
                    }
                }
            });
            //bootbox.confirm($translate.instant("apToPvc"), function(result) {
            //    if(result) {
            //        lockScreen.lock();
            //        var operatorMsg = "update2pvc_log_name";
            //        var loginfo = [{
            //            'ip':$scope.currentApInfo.ip,
            //            'success':"module_operate_failure",
            //            'msg':''}];
            //        var operatorMsg1 = "update2vc_log_name";
            //        var loginfo1 = [{
            //            'ip':"PVC",
            //            'success':"module_operate_failure",
            //            'msg':''}];
            //        authentifiedRequest.put(url, null, bodyParas, function(response){
            //            if(response != null && response.success){
            //                loginfo[0].success = "module_operate_success";
            //                loginfo[0].msg = "ap_log_success";
            //                //var bodyParas={"mac":$scope.aplistdetailinfo.PVC[0].mac,"role":0};
            //                var pvc_url = url_pro + $scope.aplistdetailinfo.PVC[0].ip + url_port+"/prioritychange";
            //                authentifiedRequest.put(pvc_url, null, bodyParas, function(response){
            //                    if(response != null && response.success){
            //                        toastr.info($translate.instant("changeRoleS"), '');
            //                        loginfo1[0].success = "module_operate_success";
            //                        loginfo1[0].msg = "ap_log_success";
            //                        var operatorBashMsg = "restart_ap_cluster_log_name";
            //                        batchSyncConfig.request("put","/reloadclt",null, null, null, null,operatorBashMsg);
            //                        lockScreen.unlock();
            //                    }else{
            //                        loginfo1[0].success = "module_operate_failure";
            //                        loginfo1[0].msg = "ap_log_error_1";
            //                        toastr.warning($translate.instant("changeRoleF"), '');
            //                        lockScreen.unlock();
            //                    }
            //                    operationLog.setLog(operatorMsg1, loginfo1, null);
            //                }, function(){
            //                    loginfo1[0].success = "module_operate_failure";
            //                    loginfo1[0].msg = 'failedServer';
            //                    operationLog.setLog(operatorMsg1, loginfo1, null);
            //                    toastr.warning($translate.instant("failedServer"));
            //                    lockScreen.unlock();
            //                })
            //            }else{
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = "ap_log_error_1";
            //                toastr.warning($translate.instant("changeRoleF"), '');
            //                lockScreen.unlock();
            //            }
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //        }, function(){
            //            loginfo[0].success = "module_operate_failure";
            //            loginfo[0].msg = 'failedServer';
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //            toastr.warning($translate.instant("failedServer"));
            //            lockScreen.unlock();
            //        });
            //    }
            //});
        }


        $scope.saveOrCancelApLocation = function(type){
            if(type==100){
                $scope.editloc.aploc = "";
                $scope.flag.noeditloc = false;
            }else if(type==101){
                var url = url_pro + $scope.currentApInfo.ip + url_port+"/chgaploc";
                var bodyParas= {"mac":$scope.currentApInfo.mac,"aploc":$scope.editloc.aploc};
                lockScreen.lock();
                var operatorMsg = "modify_ap_location_log_name";
                var loginfo = [{
                    'ip':$scope.currentApInfo.ip,
                    'success':"module_operate_failure",
                    'msg':''}];
                authentifiedRequest.put(url, null, bodyParas, function(response){
                    if(response != null && response.success){
                        $scope.apInfo.apLoc = $scope.editloc.aploc;
                        $scope.flag.noeditloc = true;
                        loginfo[0].success = "module_operate_success";
                        loginfo[0].msg = "ap_log_success";
                        lockScreen.unlock();
                    }else{
                        lockScreen.unlock();
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = "ap_log_error_1";
                        toastr.warning($translate.instant("modifyLocationApF"));
                    }
                    operationLog.setLog(operatorMsg, loginfo, null);
                }, function(){
                    lockScreen.unlock();
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = 'failedServer';
                    operationLog.setLog(operatorMsg, loginfo, null);
                    toastr.warning($translate.instant("failedServer"));
                });
            }else if(type==102){
                $scope.flag.noeditloc = true;
                $scope.editloc.aploc = "";
            }
        }


        $scope.show_ip_edit = function (type) {
            if(type==100){
                $scope.flag.isEditip=false;
            }else if(type==101){
                $scope.flag.isEditip=true;
            }
        }

        //edit dhcp
        $scope.saveDhcpOpration = function(type){
            if(type==100){
                $scope.flag.showdhcp=false;
                $scope.edit = {"apNewName":"","mac":"","proto":"","ipaddr":"","netmask":"","gateway":""};
                if($scope.apInfo.netproto.toUpperCase() == "STATIC"){
                    $scope.edit.proto="static";
                    $scope.flag.isEditip=true;
                }else{
                    $scope.edit.proto="dhcp";
                    $scope.flag.isEditip=false;
                }
            }else if(type==101){
                $scope.edit.mac = $scope.currentApInfo.mac;
                var url = url_pro + $scope.currentApInfo.ip + url_port+"/chgnetaddr";
                var url_reload = url_pro + $scope.currentApInfo.ip + url_port+"/reload";
                var bodyParas=$scope.edit;
                lockScreen.lock();
                var operatorMsg = "modify_ap_ip_log_name";
                var loginfo = [{
                    'ip':$scope.currentApInfo.ip,
                    'success':"module_operate_failure",
                    'msg':''}];
                authentifiedRequest.put(url, null, bodyParas, function(response){
                    if(response != null && response.success){
                        authentifiedRequest.get(url_reload, null, function(response){}, function(){});
                        $scope.flag.showdhcp=true;
                        lockScreen.unlock();
                        loginfo[0].success = "module_operate_success";
                        loginfo[0].msg = "ap_log_success";
                        toastr.info($translate.instant("modifyIpApS"), '');
                    }else{
                        lockScreen.unlock();
                        toastr.warning($translate.instant("modifyIpApF"), '');
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = "ap_log_error_1";
                    }
                    operationLog.setLog(operatorMsg, loginfo, null);
                }, function(){
                    lockScreen.unlock();
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = 'failedServer';
                    operationLog.setLog(operatorMsg, loginfo, null);
                    toastr.warning($translate.instant("failedServer"));
                });
            }else if(type==102){
                $scope.flag.showdhcp=true;
            }
        }
        /*******************right function end**************************/

        /*******************bottom function start**************************/
        $scope.clearAllCfg = function() {
            $scope.flag.upload2one=true;
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("clearConfigurationAllAp"),
                callback: function(result) {
                    if(result) {
                        var operatorMsg = "clear_configuration_log_name";
                        batchSyncConfig.request("put","/clearallcfg",null,null,null,null,operatorMsg);
                    }
                }
            });
            //bootbox.confirm($translate.instant("clearConfigurationAllAp"), function(result) {
            //    if(result) {
            //        var operatorMsg = "clear_configuration_log_name";
            //        batchSyncConfig.request("put","/clearallcfg",null,null,null,null,operatorMsg);
            //    }
            //});
        }

        /*$scope.backupAllCfg = function () {
                var url = url_pro+$scope.aplistdetailinfo.PVC[0].ip+url_port+"/backupcfg";
                var frame = $("<iframe style='display: none;'/>");
                frame.appendTo($("body")).attr({ "src": url, "display": "block" });
                setTimeout(function () {
                    frame.remove();
                }, 30000);
        }*/

        $scope.downloadServerDetailList = function(x){
            $scope.flag.upload2one=true;
            var operatorMsg = "download_ap_configration_log_name";
            var loginfo = [{
                'ip':"PVC",
                'success':"module_operate_failure",
                'msg':''}];
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("backupConfiguration"),
                callback: function(result) {
                    if(result) {

                        $http({
                            method: 'get',
                            url: "/backupcfg",
                            headers: {
                                'Authorization': 'sessionName ' + window.localStorage.sessionId
                            }
                        }).success( function(data, status, headers) {
                            var octetStreamMime = 'application/octet-stream';
                            var success = false;
                            headers = headers();
                            var filename_str = headers['content-disposition'];
                            var strs= new Array();
                            strs=filename_str.split("=");
                            var filename=strs[1];
                            var contentType = headers['content-type'] || octetStreamMime;
                            try
                            {
                                //console.log("Trying saveBlob method ...");
                                var blob = new Blob([data], { type: contentType });
                                if(navigator.msSaveBlob) {
                                    navigator.msSaveBlob(blob, filename);
                                }
                                else {
                                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
                                    if(saveBlob === undefined) throw "Not supported";
                                    else{
                                        saveBlob(blob, filename);
                                    }
                                    //console.log("saveBlob succeeded");
                                    success = true;
                                }
                            }catch(ex) {
                                //console.log("saveBlob method failed with the following exception:");
                                console.log(ex);
                            }
                            if(!success){
                                var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
                                if(urlCreator){
                                    var link = document.createElement('a');
                                    if('download' in link){
                                        try {
                                            //console.log("Trying download link method with simulated click ...");
                                            var blob = new Blob([data], { type: contentType });
                                            var url = urlCreator.createObjectURL(blob);
                                            link.setAttribute('href', url);
                                            link.setAttribute("download", filename);
                                            var event = document.createEvent('MouseEvents');
                                            event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
                                            link.dispatchEvent(event);
                                            //console.log("Download link method with simulated click succeeded");
                                            success = true;
                                        } catch(ex) {
                                            //console.log("Download link method with simulated click failed with the following exception:");
                                            console.log(ex);
                                        }
                                    }
                                    if(!success){
                                        try{
                                            //console.log("Trying download link method with window.location ...");
                                            var blob = new Blob([data], { type: octetStreamMime });
                                            var url = urlCreator.createObjectURL(blob);
                                            window.location = url;
                                            //console.log("Download link method with window.location succeeded");
                                            success = true;
                                        }catch(ex) {
                                            //console.log("Download link method with window.location failed with the following exception:");
                                            console.log(ex);
                                        }
                                    }
                                }
                            }
                            if(!success)
                            {
                                // console.log("No methods worked for saving the arraybuffer, using last resort window.open");
                                // window.open(httpPath, '_blank', '');
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = 'ap_log_error_2';
                                toastr.warning($translate.instant("faileddownload"));
                            }else{
                                loginfo[0].success = "module_operate_success";
                                loginfo[0].msg = "ap_log_success";

                            }
                            operationLog.setLog(operatorMsg, loginfo, null);
                        })
                            .error(function(data, status) {
                                console.log("Request failed with status: " + status);
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = 'failedServer';
                                operationLog.setLog(operatorMsg, loginfo, null);
                                toastr.warning($translate.instant("failedServer"));
                            });
                    }
                }
            });
            //bootbox.confirm($translate.instant("backupConfiguration"), function(result) {
            //    if(result){
            //        $http({
            //            method: 'get',
            //            url: "/backupcfg",
            //            headers: {
            //                'Authorization': 'sessionName ' + window.localStorage.sessionId
            //            }
            //        }).success( function(data, status, headers) {
            //            var octetStreamMime = 'application/octet-stream';
            //            var success = false;
            //            headers = headers();
            //            var filename_str = headers['content-disposition'];
            //            var strs= new Array();
            //            strs=filename_str.split("=");
            //            var filename=strs[1];
            //            var contentType = headers['content-type'] || octetStreamMime;
            //            try
            //            {
            //                //console.log("Trying saveBlob method ...");
            //                var blob = new Blob([data], { type: contentType });
            //                if(navigator.msSaveBlob) {
            //                    navigator.msSaveBlob(blob, filename);
            //                }
            //                else {
            //                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
            //                    if(saveBlob === undefined) throw "Not supported";
            //                    else{
            //                        saveBlob(blob, filename);
            //                    }
            //                    //console.log("saveBlob succeeded");
            //                    success = true;
            //                }
            //            }catch(ex) {
            //                //console.log("saveBlob method failed with the following exception:");
            //                console.log(ex);
            //            }
            //            if(!success){
            //                var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
            //                if(urlCreator){
            //                    var link = document.createElement('a');
            //                    if('download' in link){
            //                        try {
            //                            //console.log("Trying download link method with simulated click ...");
            //                            var blob = new Blob([data], { type: contentType });
            //                            var url = urlCreator.createObjectURL(blob);
            //                            link.setAttribute('href', url);
            //                            link.setAttribute("download", filename);
            //                            var event = document.createEvent('MouseEvents');
            //                            event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
            //                            link.dispatchEvent(event);
            //                            //console.log("Download link method with simulated click succeeded");
            //                            success = true;
            //                        } catch(ex) {
            //                            //console.log("Download link method with simulated click failed with the following exception:");
            //                            console.log(ex);
            //                        }
            //                    }
            //                    if(!success){
            //                        try{
            //                            //console.log("Trying download link method with window.location ...");
            //                            var blob = new Blob([data], { type: octetStreamMime });
            //                            var url = urlCreator.createObjectURL(blob);
            //                            window.location = url;
            //                            //console.log("Download link method with window.location succeeded");
            //                            success = true;
            //                        }catch(ex) {
            //                            //console.log("Download link method with window.location failed with the following exception:");
            //                            console.log(ex);
            //                        }
            //                    }
            //                }
            //            }
            //            if(!success)
            //            {
            //                // console.log("No methods worked for saving the arraybuffer, using last resort window.open");
            //                // window.open(httpPath, '_blank', '');
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = 'ap_log_error_2';
            //                toastr.warning($translate.instant("faileddownload"));
            //            }else{
            //                loginfo[0].success = "module_operate_success";
            //                loginfo[0].msg = "ap_log_success";
            //
            //            }
            //            operationLog.setLog(operatorMsg, loginfo, null);
            //        })
            //            .error(function(data, status) {
            //                console.log("Request failed with status: " + status);
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = 'failedServer';
            //                operationLog.setLog(operatorMsg, loginfo, null);
            //                toastr.warning($translate.instant("failedServer"));
            //            });
            //
            //    }
            //});


        };

        $scope.num=0;
        var uploader = $scope.uploader = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });

        uploader.onAfterAddingFile  = function(fileItem) {
            var regex =/^[\w- ()]+\.conf$/;
            var result=regex.test((fileItem.file.name).toLowerCase());
            if(!result){
                $scope.clearItems();
                toastr.warning($translate.instant("fileFormatConf"), '');
                return;
            }
            var size = Math.floor(fileItem.file.size/1024/1024);
            if(size>20){
                $scope.clearItems();
                toastr.warning($translate.instant("file_too_big"), '');
                return;
            }
        };

        /*uploader.onCompleteAll = function() {
            $scope.num++;
             if(($scope.num < $scope.aplistdetailinfo.working.length)&& $scope.uploadflag.connect){
                $scope.restorefile(uploader.queue[0]);
             }else{
                 if($scope.uploadflag.connect){
                     $scope.restorefile(uploader.queue[0]);
                 }else{
                     $scope.num=0;
                     $scope.clearItems();
                 }
             }
         };*/

        function show_restore_tip(item,response,status){
            var operatorMsg = "restore_configration_log_name";
            var loginfo = [{
                'ip':item.ip,
                'success':"module_operate_failure",
                'msg':''}];

            if((status ==200) && (response.success == true)){
                loginfo[0].success = "module_operate_success";
                loginfo[0].msg = "ap_log_success";
                if($scope.uploadflag.mac.toUpperCase() == item.mac.toUpperCase()){
                    setOutTime2Login();
                }
                toastr.info('IP:'+item.ip+'&nbsp;'+$translate.instant("apRestoreInfo"), '');
            }else{
                if(status ==200){
                    if(response.result == '100'){
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = 'ap_restore_error_1';
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("ap_restore_error_1"), '');
                    }else if(response.result == '101'){
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = 'ap_restore_error_2';
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("ap_restore_error_2"), '');
                    }else if(response.result == '102'){
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = 'ap_restore_error_3';
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("ap_restore_error_3"), '');
                    }else if(response.result == '103'){
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = 'ap_restore_error_4';
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("ap_restore_error_4"), '');
                    }else{
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = "ap_log_error_1";
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("ap_log_error_1"), '');
                    }
                }else{
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = 'failedServer';
                    toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("msg_base")+$translate.instant("failedServer"), '');
                }
                if($scope.uploadflag.mac.toUpperCase() == item.mac.toUpperCase()){
                    lockScreen.unlock();
                }
            }
            operationLog.setLog(operatorMsg, loginfo, null);
        }

        uploader.onCompleteItem = function(item, response, status, headers){
             show_restore_tip($scope.aplistdetailinfo.working[$scope.num], response, status);
             $scope.num++;
             if(($scope.num < $scope.aplistdetailinfo.working.length)&& $scope.uploadflag.connect){
                $scope.restorefile(uploader.queue[0]);
             }else{
                 if($scope.uploadflag.connect){
                     $scope.restorefile(uploader.queue[0]);
                 }else{
                     $scope.num=0;
                 }
             }
        }


        function uploadconfigfuc(item){
            lockScreen.lock(420000);
            var mac= $scope.aplistdetailinfo.working[$scope.num].mac.toUpperCase();
            var record_mac= $scope.uploadflag.mac.toUpperCase();
            if((record_mac == mac)&& $scope.uploadflag.connect) {
                $scope.uploadflag.num = $scope.num;
                $scope.num = $scope.num+1;
                if($scope.num < $scope.aplistdetailinfo.working.length){
                    item.url=url_pro+$scope.aplistdetailinfo.working[$scope.num].ip+url_port+"/restorecfg/"+item.file.name;
                    item.upload();
                }else{
                    $scope.restorefile(uploader.queue[0]);
                }
            }else{
                item.url=url_pro+$scope.aplistdetailinfo.working[$scope.num].ip+url_port+"/restorecfg/"+item.file.name;
                item.upload();
            }
        }

         $scope.restorefile = function(item) {
             if(!$scope.uploadflag.connect){
                 bootbox.confirm({
                     buttons: {
                         cancel: {
                             label: $translate.instant("Cancel")
                         },
                         confirm: {
                             label: $translate.instant("OK")
                         }
                     },
                     message: $translate.instant("restoreConfiguration"),
                     callback: function(result) {
                         if(result) {
                             if($scope.aplistdetailinfo.working.length<1){
                                 toastr.warning($translate.instant("havingNoApRestore"), '');
                                 return;
                             }

                             if($scope.uploadflag.mac == ""){
                                 getCurrentApInfo();
                                 toastr.warning($translate.instant("failedLocateConnAp"));
                             }else{
                                 $scope.uploadflag.connect = true;
                                 uploadconfigfuc(item);
                             }
                         }
                     }
                 });
                 //bootbox.confirm($translate.instant("restoreConfiguration"), function(result) {
                 //   if(result) {
                 //        if($scope.aplistdetailinfo.working.length<1){
                 //            toastr.warning($translate.instant("havingNoApRestore"), '');
                 //            return;
                 //        }
                 //
                 //       if($scope.uploadflag.mac == ""){
                 //           getCurrentApInfo();
                 //           toastr.warning($translate.instant("failedLocateConnAp"));
                 //       }else{
                 //           $scope.uploadflag.connect = true;
                 //           uploadconfigfuc(item);
                 //       }
                 //   }
                 //});
             }else{
                 if(!($scope.num < $scope.aplistdetailinfo.working.length)){
                     $scope.num = $scope.uploadflag.num;
                     $scope.uploadflag.connect = false;
                 }
                 uploadconfigfuc(item);
             }
         }

        $scope.clearItems = function(){
            uploader.clearQueue();
        }


        $scope.checkAll = function(state){
            angular.forEach($scope.aplistinfo, function(item) {
                if(item.state==3){
                    item.$checked = state;
                }
            });
        };

        /*function selection(){
            return _.where($scope.aplistinfo, {$checked: true});
        };*/

        /*******upload version method 1 start********/

        function writeLog(itemIp, itemMac, response){
            var operatorMsg = "upgrade_verion_log_name";
            var loginfo = [{
                'ip':itemIp,
                'success':"module_operate_failure",
                'msg':''}];
            loginfo[0].success = response.flag;
            loginfo[0].msg = response.msg;
            if(! response.flag){
               toastr.warning('IP:'+itemIp+'&nbsp;'+$translate.instant(response.msg), ''); 
            }else{
                if($scope.uploadflag.mac.toUpperCase() == itemMac.toUpperCase()){
                    $scope.uploadflag.byurlflag = true;
                    setOutTime2Login();
                }
                toastr.info('IP:'+itemIp+'&nbsp;'+$translate.instant(response.msg), '');
            }
            operationLog.setLog(operatorMsg, loginfo, null);
        }

        $scope.UpdateByUrl = function(type){
            var bodypara = $scope.byurl;
            if(type==100){
                if($scope.aplistdetailinfo.working.length<1){
                    toastr.warning($translate.instant("havingNoApUpgrade"), '');
                }else{
                    bootbox.confirm({
                        buttons: {
                            cancel: {
                                label: $translate.instant("Cancel")
                            },
                            confirm: {
                                label: $translate.instant("OK")
                            }
                        },
                        message: $translate.instant("osupgradeVersionAllAp"),
                        callback: function(result) {
                            if(result) {
                                batchSyncConfig.putAll("/updatebyurl", bodypara,function(response){
                                    for(var inter_res=0; inter_res<response.length; inter_res++){
                                        var resmac = response[inter_res].mac.toUpperCase() ;
                                        var inter_flag=false;
                                        var mac = $scope.aplistdetailinfo.PVC[0].mac.toUpperCase() ;
                                        if(mac == resmac){
                                            if(! response[inter_res].flag){
                                                $scope.aplistdetailinfo.PVC[0].uploadFaseFlag = 101;
                                                writeLog($scope.aplistdetailinfo.PVC[0].ip, $scope.aplistdetailinfo.PVC[0].mac, response[inter_res]);
                                                inter_flag=true;
                                            }else{
                                                $scope.aplistdetailinfo.PVC[0].uploadFaseFlag = 102;
                                                writeLog($scope.aplistdetailinfo.PVC[0].ip,$scope.aplistdetailinfo.PVC[0].mac, response[inter_res]);
                                            }
                                        }
                                        if(! inter_flag){
                                            for(var i=0; i<$scope.aplistdetailinfo.SVC.length; i++){
                                                var mac = $scope.aplistdetailinfo.SVC[i].mac.toUpperCase() ;
                                                if(mac == resmac){
                                                    if(! response[inter_res].flag){
                                                        $scope.aplistdetailinfo.SVC[i].uploadFaseFlag = 101;
                                                        writeLog($scope.aplistdetailinfo.SVC[i].ip, $scope.aplistdetailinfo.SVC[i].mac, response[inter_res]);
                                                        inter_flag=true;
                                                    }else{
                                                        $scope.aplistdetailinfo.SVC[i].uploadFaseFlag = 102;
                                                        writeLog($scope.aplistdetailinfo.SVC[i].ip, $scope.aplistdetailinfo.SVC[i].mac, response[inter_res]);
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                        if(! inter_flag){
                                            for(var i=0; i<$scope.aplistdetailinfo.MEM.length; i++){
                                                var mac = $scope.aplistdetailinfo.MEM[i].mac.toUpperCase() ;
                                                if(mac == resmac){
                                                    if(! response[inter_res].flag){
                                                        $scope.aplistdetailinfo.MEM[i].uploadFaseFlag = 101;
                                                        writeLog($scope.aplistdetailinfo.MEM[i].ip, $scope.aplistdetailinfo.MEM[i].mac, response[inter_res]);
                                                        inter_flag=true;
                                                    }else{
                                                        $scope.aplistdetailinfo.MEM[i].uploadFaseFlag = 102;
                                                        writeLog($scope.aplistdetailinfo.MEM[i].ip, $scope.aplistdetailinfo.MEM[i].mac, response[inter_res]);
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    if(!$scope.uploadflag.byurlflag){
                                        lockScreen.unlock();
                                    }
                                    $scope.uploadflag.byurlflag = false;
                                }, 840000);
                            }
                        }
                    });
                    //bootbox.confirm($translate.instant("osupgradeVersionAllAp"), function(result) {
                    //    if(result){
                    //        batchSyncConfig.putAll("/updatebyurl", bodypara,function(response){
                    //            for(var inter_res=0; inter_res<response.length; inter_res++){
                    //                var resmac = response[inter_res].mac.toUpperCase() ;
                    //                var inter_flag=false;
                    //                var mac = $scope.aplistdetailinfo.PVC[0].mac.toUpperCase() ;
                    //                if(mac == resmac){
                    //                    if(! response[inter_res].flag){
                    //                        $scope.aplistdetailinfo.PVC[0].uploadFaseFlag = 101;
                    //                        writeLog($scope.aplistdetailinfo.PVC[0].ip, $scope.aplistdetailinfo.PVC[0].mac, response[inter_res]);
                    //                        inter_flag=true;
                    //                    }else{
                    //                        $scope.aplistdetailinfo.PVC[0].uploadFaseFlag = 102;
                    //                        writeLog($scope.aplistdetailinfo.PVC[0].ip,$scope.aplistdetailinfo.PVC[0].mac, response[inter_res]);
                    //                    }
                    //                }
                    //                if(! inter_flag){
                    //                    for(var i=0; i<$scope.aplistdetailinfo.SVC.length; i++){
                    //                        var mac = $scope.aplistdetailinfo.SVC[i].mac.toUpperCase() ;
                    //                        if(mac == resmac){
                    //                            if(! response[inter_res].flag){
                    //                                $scope.aplistdetailinfo.SVC[i].uploadFaseFlag = 101;
                    //                                writeLog($scope.aplistdetailinfo.SVC[i].ip, $scope.aplistdetailinfo.SVC[i].mac, response[inter_res]);
                    //                                inter_flag=true;
                    //                            }else{
                    //                                $scope.aplistdetailinfo.SVC[i].uploadFaseFlag = 102;
                    //                                writeLog($scope.aplistdetailinfo.SVC[i].ip, $scope.aplistdetailinfo.SVC[i].mac, response[inter_res]);
                    //                            }
                    //                            break;
                    //                        }
                    //                    }
                    //                }
                    //                if(! inter_flag){
                    //                    for(var i=0; i<$scope.aplistdetailinfo.MEM.length; i++){
                    //                        var mac = $scope.aplistdetailinfo.MEM[i].mac.toUpperCase() ;
                    //                        if(mac == resmac){
                    //                            if(! response[inter_res].flag){
                    //                                $scope.aplistdetailinfo.MEM[i].uploadFaseFlag = 101;
                    //                                writeLog($scope.aplistdetailinfo.MEM[i].ip, $scope.aplistdetailinfo.MEM[i].mac, response[inter_res]);
                    //                                inter_flag=true;
                    //                            }else{
                    //                                $scope.aplistdetailinfo.MEM[i].uploadFaseFlag = 102;
                    //                                writeLog($scope.aplistdetailinfo.MEM[i].ip, $scope.aplistdetailinfo.MEM[i].mac, response[inter_res]);
                    //                            }
                    //                            break;
                    //                        }
                    //                    }
                    //                }
                    //            }
                    //            if(!$scope.uploadflag.byurlflag){
                    //                lockScreen.unlock();
                    //            }
                    //            $scope.uploadflag.byurlflag = false;
                    //        }, 840000);
                    //    }
                    //});
                }
            }else if(type ==200){
                bootbox.confirm({
                    buttons: {
                        cancel: {
                            label: $translate.instant("Cancel")
                        },
                        confirm: {
                            label: $translate.instant("OK")
                        }
                    },
                    message: $translate.instant("osupgradeVersionAp"),
                    callback: function(result) {
                        if(result) {

                            var url = url_pro + $scope.currentApInfo.ip + url_port+"/updatebyurl";
                            var operatorMsg = "upgrade_verion_log_name";
                            var loginfo = [{
                                'ip':$scope.currentApInfo.ip,
                                'success':"module_operate_failure",
                                'msg':''}];
                            lockScreen.lock(180000);
                            if($scope.currentApInfo.state == 1){//joining 绕过session校验
                                var data = {};
                                data.username = window.localStorage.username;
                                data.sessionId = window.localStorage.sessionId;
                                data.flag = 1;
                                $http({
                                    method: 'post',
                                    url: url_pro+$scope.currentApInfo.ip+url_port+'/authentication/syncSessionId',
                                    data: data,
                                    timeout: 15000,
                                    headers: {
                                        'Content-Type': 'application/json'
                                    }
                                }).success(function(res) {
                                    authentifiedRequest.request('put', url, null, bodypara, 180000, function(response){
                                        if(response != null && response.success){
                                            loginfo[0].success = response.result.flag;
                                            loginfo[0].msg = response.result.msg;
                                            if($scope.currentApInfo.mac.toUpperCase() == $scope.uploadflag.mac.toUpperCase()){
                                                setOutTime2Login();
                                            }else{
                                                lockScreen.unlock();
                                            }
                                            toastr.info('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant(response.result.msg), '');
                                        }else{
                                            loginfo[0].success = "module_operate_failure";
                                            loginfo[0].msg = "ap_log_error_1";
                                            lockScreen.unlock();
                                            toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant("uploadVersionByUrlF"), '');
                                        }
                                        operationLog.setLog(operatorMsg, loginfo, null);
                                    }, function(){
                                        lockScreen.unlock();
                                        toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;msg:'+$translate.instant("failedServer"), '');
                                        loginfo[0].success = "module_operate_failure";
                                        loginfo[0].msg = 'failedServer';
                                        operationLog.setLog(operatorMsg, loginfo, null);
                                    });

                                })
                            }else{
                                authentifiedRequest.request('put', url, null, bodypara, 180000, function(response){
                                    if(response != null && response.success){
                                        loginfo[0].success = response.result.flag;
                                        loginfo[0].msg = response.result.msg;
                                        if($scope.currentApInfo.mac.toUpperCase() == $scope.uploadflag.mac.toUpperCase()){
                                            setOutTime2Login();
                                        }else{
                                            lockScreen.unlock();
                                        }
                                        toastr.info('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant(response.result.msg), '');
                                    }else{
                                        loginfo[0].success = "module_operate_failure";
                                        loginfo[0].msg = "ap_log_error_1";
                                        lockScreen.unlock();
                                        toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant("uploadVersionByUrlF"), '');
                                    }
                                    operationLog.setLog(operatorMsg, loginfo, null);
                                }, function(){
                                    lockScreen.unlock();
                                    toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;msg:'+$translate.instant("failedServer"), '');
                                    loginfo[0].success = "module_operate_failure";
                                    loginfo[0].msg = 'failedServer';
                                    operationLog.setLog(operatorMsg, loginfo, null);
                                });
                            }
                        }
                    }
                });
                //bootbox.confirm($translate.instant("osupgradeVersionAp"), function(result) {
                //    if(result){
                //        var url = url_pro + $scope.currentApInfo.ip + url_port+"/updatebyurl";
                //        var operatorMsg = "upgrade_verion_log_name";
                //        var loginfo = [{
                //            'ip':$scope.currentApInfo.ip,
                //            'success':"module_operate_failure",
                //            'msg':''}];
                //        lockScreen.lock(180000);
                //        if($scope.currentApInfo.state == 1){//joining 绕过session校验
                //            var data = {};
                //            data.username = window.localStorage.username;
                //            data.sessionId = window.localStorage.sessionId;
                //            data.flag = 1;
                //            $http({
                //                method: 'post',
                //                url: url_pro+$scope.currentApInfo.ip+url_port+'/authentication/syncSessionId',
                //                data: data,
                //                timeout: 15000,
                //                headers: {
                //                    'Content-Type': 'application/json'
                //                }
                //            }).success(function(res) {
                //                 authentifiedRequest.request('put', url, null, bodypara, 180000, function(response){
                //                    if(response != null && response.success){
                //                        loginfo[0].success = response.result.flag;
                //                        loginfo[0].msg = response.result.msg;
                //                        if($scope.currentApInfo.mac.toUpperCase() == $scope.uploadflag.mac.toUpperCase()){
                //                            setOutTime2Login();
                //                        }else{
                //                            lockScreen.unlock();
                //                        }
                //                        toastr.info('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant(response.result.msg), '');
                //                    }else{
                //                        loginfo[0].success = "module_operate_failure";
                //                        loginfo[0].msg = "ap_log_error_1";
                //                        lockScreen.unlock();
                //                        toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant("uploadVersionByUrlF"), '');
                //                    }
                //                    operationLog.setLog(operatorMsg, loginfo, null);
                //                }, function(){
                //                    lockScreen.unlock();
                //                    toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;msg:'+$translate.instant("failedServer"), '');
                //                    loginfo[0].success = "module_operate_failure";
                //                    loginfo[0].msg = 'failedServer';
                //                    operationLog.setLog(operatorMsg, loginfo, null);
                //                });
                //
                //            })
                //        }else{
                //            authentifiedRequest.request('put', url, null, bodypara, 180000, function(response){
                //                if(response != null && response.success){
                //                    loginfo[0].success = response.result.flag;
                //                    loginfo[0].msg = response.result.msg;
                //                    if($scope.currentApInfo.mac.toUpperCase() == $scope.uploadflag.mac.toUpperCase()){
                //                        setOutTime2Login();
                //                    }else{
                //                        lockScreen.unlock();
                //                    }
                //                    toastr.info('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant(response.result.msg), '');
                //                }else{
                //                    loginfo[0].success = "module_operate_failure";
                //                    loginfo[0].msg = "ap_log_error_1";
                //                    lockScreen.unlock();
                //                    toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;'+$translate.instant("uploadVersionByUrlF"), '');
                //                }
                //                operationLog.setLog(operatorMsg, loginfo, null);
                //            }, function(){
                //                lockScreen.unlock();
                //                toastr.warning('IP:'+$scope.currentApInfo.ip+'&nbsp;msg:'+$translate.instant("failedServer"), '');
                //                loginfo[0].success = "module_operate_failure";
                //                loginfo[0].msg = 'failedServer';
                //                operationLog.setLog(operatorMsg, loginfo, null);
                //            });
                //        }
                //    }
                //});
            }
        }
        /*******upload version method 1 end********/
        /*******upload version method 2 start********/
        var uploaderfirm = $scope.uploaderfirm = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });
        $scope.updatetype = 0;

        $scope.clearItemsfirm = function(){
            uploaderfirm.clearQueue();
        }

        uploaderfirm.onAfterAddingFile = function(fileItem) {
            //var regex =/^[\w-]+\.bin$/;
            var regex =/^[\w-\.]+\.bin$/;
            var result=regex.test((fileItem.file.name).toLowerCase());
            if(!result){
                $scope.clearItemsfirm();
                toastr.warning($translate.instant("fileFormatbin"), '');
                return;
            }
            var size = Math.floor(fileItem.file.size/1024/1024);
            if(size>20){
                $scope.clearItemsfirm();
                toastr.warning($translate.instant("file_too_big"), '');
                return;
            }
        };
        function edit_firm_false_flag(item, type){
            if(item.role==1) {
                $scope.aplistdetailinfo.PVC[0].uploadFaseFlag = type;
            }else if(item.role==2){
                for(var i=0; i< $scope.aplistdetailinfo.SVC.length; i++){
                    if(item.mac == $scope.aplistdetailinfo.SVC[i].mac){
                        $scope.aplistdetailinfo.SVC[i].uploadFaseFlag = type;
                        break;
                    }
                }
            }else if(item.role==3){
                for(var i=0; i< $scope.aplistdetailinfo.MEM.length; i++){
                    if(item.mac == $scope.aplistdetailinfo.MEM[i].mac){
                        $scope.aplistdetailinfo.MEM[i].uploadFaseFlag = type;
                        break;
                    }
                }
            }
        }

        function show_firm_tip(item,response,status, type){
            var operatorMsg = "upgrade_version_http_log_name";
            var loginfo = [{
                'ip':item.ip,
                'success':"module_operate_failure",
                'msg':''}];

            if((status ==200) && (response.success == true)){
                edit_firm_false_flag(item, 102);
                if(type ==1){
                    if($scope.uploadflag.mac.toUpperCase() == item.mac.toUpperCase()){
                        setOutTime2Login();
                    }else{
                        lockScreen.unlock();
                    }
                }else{
                    if($scope.uploadflag.mac.toUpperCase() == item.mac.toUpperCase()){
                        setOutTime2Login();
                    }
                }
                loginfo[0].success = "module_operate_success";
                loginfo[0].msg = "ap_log_success";
                toastr.info('IP:'+item.ip+'&nbsp;'+$translate.instant("uploadVersionByUrlS"), '');
            }else{
                if(status ==200){
                    if(response.result == '100'){
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = 'ap_log_error_3';
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("noMemoryOsupgrade"), '');
                    }else{
                        loginfo[0].success = "module_operate_failure";
                        loginfo[0].msg = 'ap_log_error_4';
                        toastr.warning('IP:'+item.ip+'&nbsp;'+$translate.instant("osupgradeF"), '');
                    }
                }else{
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = 'failedServer';
                    toastr.warning('IP:'+item.ip+'&nbsp;msg:'+$translate.instant("failedServer"), '');
                }

                if(type ==1){
                    lockScreen.unlock();
                }else{
                    if($scope.uploadflag.mac.toUpperCase() == item.mac.toUpperCase()){
                        lockScreen.unlock();
                    }
                }
                edit_firm_false_flag(item, 101);
            }
            operationLog.setLog(operatorMsg, loginfo, null);
        }

        uploaderfirm.onCompleteItem = function(item, response, status, headers){
            if($scope.updatetype ==1){
                $scope.num=0;
                show_firm_tip($scope.currentApInfo, response, status, 1);
            }else if($scope.updatetype ==2){
                show_firm_tip($scope.aplistdetailinfo.working[$scope.num], response, status, 2);
                $scope.num++;
                if($scope.num < $scope.aplistdetailinfo.working.length && $scope.uploadflag.connect){
                    $scope.UpdatetoAll(uploaderfirm.queue[0],2);
                }else{
                    if($scope.uploadflag.connect){
                        $scope.UpdatetoAll(uploaderfirm.queue[0],2);
                    }else{
                        $scope.num=0;
                    }
                }
            }
        }

       /* uploaderfirm.onCompleteAll = function() {
            if($scope.updatetype ==1){
                $scope.num=0;
                toastr.info('IP:'+$scope.currentApInfo.ip+'&nbsp;msg:Version has been uploaded successfully. The AP is being upgraded !', '');
                $scope.clearItemsfirm();
            }else if($scope.updatetype ==2){
                toastr.info('IP:'+$scope.aplistdetailinfo.working[$scope.num].ip+'&nbsp;msg:Version has been uploaded successfully. The AP is being upgraded !', '');
                $scope.num++;
                if($scope.num < $scope.aplistdetailinfo.working.length && $scope.uploadflag.connect){
                        $scope.UpdatetoAll(uploaderfirm.queue[0],2);
                }else{
                    if($scope.uploadflag.connect){
                        $scope.UpdatetoAll(uploaderfirm.queue[0],2);
                    }else{
                        $scope.num=0;
                        $scope.clearItemsfirm();
                    }
                }
            }
        };*/

        function uploadfirmfuc(item){
            lockScreen.lock(420000);
            var mac= $scope.aplistdetailinfo.working[$scope.num].mac.toUpperCase();
            var record_mac= $scope.uploadflag.mac.toUpperCase();
            if((record_mac == mac)&& $scope.uploadflag.connect) {
                $scope.uploadflag.num = $scope.num;
                $scope.num = $scope.num+1;
                if($scope.num < $scope.aplistdetailinfo.working.length){
                    item.url=url_pro+$scope.aplistdetailinfo.working[$scope.num].ip+url_port+"/updatefirm/"+item.file.name;
                    item.upload();
                }else{
                    $scope.UpdatetoAll(uploaderfirm.queue[0],2);
                }
            }else{
                item.url=url_pro+$scope.aplistdetailinfo.working[$scope.num].ip+url_port+"/updatefirm/"+item.file.name;
                item.upload();
            }
        }

        $scope.UpdatetoAll = function(item,type) {
            $scope.updatetype = type;
            if(type==1){
                bootbox.confirm({
                    buttons: {
                        cancel: {
                            label: $translate.instant("Cancel")
                        },
                        confirm: {
                            label: $translate.instant("OK")
                        }
                    },
                    message: $translate.instant("osupgradeVersionAp"),
                    callback: function(result) {
                        if(result) {
                            if($scope.uploadflag.mac == ""){
                                getCurrentApInfo();
                                toastr.warning($translate.instant("getinfoApF"));
                            }else {
                                lockScreen.lock(420000);
                                if ($scope.currentApInfo.state ==1) {
                                    var data = {};
                                    data.username = window.localStorage.username;
                                    data.sessionId = window.localStorage.sessionId;
                                    data.flag = 1;
                                    $http({
                                        method: 'post',
                                        url: url_pro + $scope.currentApInfo.ip + url_port + '/authentication/syncSessionId',
                                        data: data,
                                        timeout: 15000,
                                        headers: {
                                            'Content-Type': 'application/json'
                                        }
                                    }).success(function (res) {
                                        item.url = url_pro + $scope.currentApInfo.ip + url_port + "/updatefirm/" + item.file.name;
                                        item.upload();

                                    })
                                }else{
                                    item.url = url_pro + $scope.currentApInfo.ip + url_port + "/updatefirm/" + item.file.name;
                                    item.upload();
                                }
                            }
                        }
                    }
                });
                //bootbox.confirm($translate.instant("osupgradeVersionAp"), function(result) {
                //    if(result){
                //        if($scope.uploadflag.mac == ""){
                //            getCurrentApInfo();
                //            toastr.warning($translate.instant("getinfoApF"));
                //        }else {
                //            lockScreen.lock(420000);
                //            if ($scope.currentApInfo.state ==1) {
                //                var data = {};
                //                data.username = window.localStorage.username;
                //                data.sessionId = window.localStorage.sessionId;
                //                data.flag = 1;
                //                $http({
                //                    method: 'post',
                //                    url: url_pro + $scope.currentApInfo.ip + url_port + '/authentication/syncSessionId',
                //                    data: data,
                //                    timeout: 15000,
                //                    headers: {
                //                        'Content-Type': 'application/json'
                //                    }
                //                }).success(function (res) {
                //                    item.url = url_pro + $scope.currentApInfo.ip + url_port + "/updatefirm/" + item.file.name;
                //                    item.upload();
                //
                //                })
                //            }else{
                //                item.url = url_pro + $scope.currentApInfo.ip + url_port + "/updatefirm/" + item.file.name;
                //                item.upload();
                //            }
                //        }
                //    }
                //});

            }else if(type==2){
                if(!$scope.uploadflag.connect){
                    bootbox.confirm({
                        buttons: {
                            cancel: {
                                label: $translate.instant("Cancel")
                            },
                            confirm: {
                                label: $translate.instant("OK")
                            }
                        },
                        message: $translate.instant("osupgradeVersionAllAp"),
                        callback: function(result) {
                            if(result) {
                                if($scope.aplistdetailinfo.working.length<1){
                                    toastr.warning($translate.instant("havingNoApUpload"), '');
                                    return;
                                }
                                if($scope.uploadflag.mac == ""){
                                    getCurrentApInfo();
                                    toastr.warning($translate.instant("getinfoApF"));
                                }else{
                                    $scope.uploadflag.connect = true;
                                    uploadfirmfuc(item);

                                }
                            }
                        }
                    });
                    //bootbox.confirm($translate.instant("osupgradeVersionAllAp"), function(result) {
                    //    if(result){
                    //        if($scope.aplistdetailinfo.working.length<1){
                    //            toastr.warning($translate.instant("havingNoApUpload"), '');
                    //            return;
                    //        }
                    //        if($scope.uploadflag.mac == ""){
                    //            getCurrentApInfo();
                    //            toastr.warning($translate.instant("getinfoApF"));
                    //        }else{
                    //            $scope.uploadflag.connect = true;
                    //            uploadfirmfuc(item);
                    //
                    //        }
                    //    }
                    //});
                }else{
                    if(!($scope.num < $scope.aplistdetailinfo.working.length)){
                        $scope.num = $scope.uploadflag.num;
                        $scope.uploadflag.connect = false;
                    }
                    uploadfirmfuc(item);
                }
            }
        }
        /*******upload version method 2 end********/

        /*******************bottom function end**************************/

        $scope.cancel = function(){
            $modalInstance.close("test");
        };
   }])
    .filter('rolechange',[function(){
        var filterfun = function(value){
            switch (value){
                case '3':
                    return 'Member';
                    break;
                case '1':
                    return 'PVC';
                    break;
                case '2':
                    return 'SVC';
                    break;
            }
        };
        return filterfun;
    }])
    .filter("apStatusFilter", [function () {
        var filterfun = function(value) {
            switch(value){
                case "1":
                    return "Joining";
                    break;
                case "2":
                    return "Initializing";
                    break;
                case "3":
                    return "Working";
                    break;
                case "4":
                    return "Down";
                    break;
            }
        };
        return filterfun;
    }])
;
