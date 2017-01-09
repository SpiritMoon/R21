angular.module('module.ap.apinfo', [])
    .service('APService', ['authentifiedRequest', 'batchSyncConfig', 'InterService', 'clientService', function(authentifiedRequest, batchSyncConfig, InterService, clientService) {
        var vm = this;

        vm.HttpGetApListInfo = function(callbackFuction) {
            var pvcinfo = InterService.getPVCinfo();
            var url="";
            if(pvcinfo==null||pvcinfo==''){
                url = "/haps";
            }else{
                //url = "http://" + pvcinfo + ":8080/haps";
                url = InterService.getProtocol()+"://"+pvcinfo+":"+InterService.getPort()+"/haps";
            }
            authentifiedRequest.get(url, null, function(data) {
                if (data != null && data.success && data.result != null) {
                    for(var i=data.result.length; i> 0 ;i-- ){
                        //edit ap state
                        if(data.result[i-1].state == 0){
                            data.result[i-1].state="1";
                        }
                        //add ap client num
                        var apsClients = clientService.getApClient(data.result[i-1].mac);
                        if(null != apsClients){
                            data.result[i-1].clients = apsClients.length;
                        }else {
                            data.result[i-1].clients = 0;
                        }
                        //add ap list name
                        if((!data.result[i-1].hasOwnProperty('name'))||(data.result[i-1].name=='') || (data.result[i-1].name ==null)){
                            data.result[i-1].apname = data.result[i-1].mac;
                        }else{
                            data.result[i-1].apname = data.result[i-1].name;
                        }
                        //add ap list version
                        if(!data.result[i-1].hasOwnProperty('version')){
                            data.result[i-1].version = " ";
                        }
                    }
                    InterService.setApListInfo(data.result);
                    if(callbackFuction != null){
                        callbackFuction();
                    }
                }
            }, function() {
            });
        }

        vm.HttpGetPvcInfo = function() {
            var url = "/pvcinfo";
            authentifiedRequest.get(url, null, function(data) {
                if (data != null && data.success && data.result != null && data.result != '') {
                    InterService.setPVCinfo(data.result);
                }
            }, function() {
            });
        }

    }])
    .controller('APController', ['$scope', '$rootScope','$translate', 'InterService', 'authentifiedRequest', 'clientService', 'monitorService','lockScreen','singleModal', 'operationLog', 'APService','toastr', function($scope, $rootScope,$translate, InterService, authentifiedRequest, clientService, monitorService,lockScreen,singleModal, operationLog, APService,toastr) {

        $scope.InterService = InterService;
        //var url_pro = "http://";
        var url_pro = InterService.getProtocol()+"://";
        //var url_port= ":8080";
        var url_port= ":"+InterService.getPort();
        $scope.apInfo = {
            "working": "0",
            "lost": "0",
            "joining": "0"
        };
        $scope.aps = InterService.getApListInfo();

        statisticApState();
        $scope.apsWidth="";
         function setApsWidth(){
            if($scope.aps.length > 7){
                $scope.apsWidth="padding-right:17px";
            }else{
                $scope.apsWidth="";
            }
        }
         setApsWidth();
        function statisticApState() {
            var work = 0;
            var join = 0;
            var lost = 0;
            for (var j = 0; j < $scope.aps.length; j++) {
                switch ($scope.aps[j].state) {
                    case "1":
                        join++;
                        var ip_flag = false;
                        var mac_str = $scope.aps[j].mac;
                        for(var i=0;i< $scope.aps.length; i++){
                            if((j != i)&&($scope.aps[j].ip == $scope.aps[i].ip)){
                                mac_str = mac_str +", " + $scope.aps[i].mac;
                                ip_flag = true;
                            }
                        }
                        if(ip_flag){
                            var tip_ip = $translate.instant("duplicate_ip_tip1") + mac_str + $translate.instant("duplicate_ip_tip2") + $scope.aps[j].ip;
                            toastr.warning(tip_ip, '');
                        }
                        break;
                    case "2":                        
                    case "3":
                        work++;
                        break;
                    case "4":
                        lost++;
                        break;
                    default:
                        break;
                }
            }           
            for (var j = 0; j < $scope.aps.length-1; j++) {
                if($scope.aps[j].state != 1){
                    continue;
                }else{
                    var ip_flag = false;
                    var mac_str="";
                    mac_str = $scope.aps[j].mac;
                    for(var i=0;i< $scope.aps.length; i++){
                        if(j != i){
                            if($scope.aps[j].ip == $scope.aps[i].ip){
                                mac_str = mac_str +"," + $scope.aps[i].mac;
                                ip_flag = true;
                            }
                        }
                    }
                    if(ip_flag){
                        var tip_ip = $translate.instant("duplicate_ip_tip") + $scope.aps[j].ip;
                        toastr.warning(tip_ip, '');
                    }
                }
            }
            $scope.apInfo = {
                "working": work,
                "lost": lost,
                "joining": join
            };
            setApsWidth();
        }


        /**/
        $scope.modal = null;
        $scope.openApinfo = function() {
           var modalInstance = singleModal.open({
                    templateUrl: 'ap/aplist.html',
                    controller: 'APinfoController',
                    size: 'lg',
                    backdrop: true
            });
           modalInstance.result.then(function(result){
                APService.HttpGetApListInfo(function(){
                    $scope.aps = InterService.getApListInfo();
                    statisticApState();
                });
           },function(reason){
                APService.HttpGetApListInfo(function(){
                    $scope.aps = InterService.getApListInfo();
                    statisticApState();
                });
           });
        };
        /*接入ap*/
        $scope.acceptAp = function(item) {
            var bodyParas = {
                "mac": item.mac
            };
            var cluster_num = $scope.aps.length - $scope.apInfo.joining;
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
                            var operatorMsg = "ap_access_group_name";
                            var loginfo = [{
                                'ip':"PVC",
                                'success':"module_operate_failure",
                                'msg':''}];
                            authentifiedRequest.put("/toauth", null, bodyParas, function(response) {
                                if (response != null && response.success) {
                                    toastr.info($translate.instant("successfullyAp"), '');
                                    APService.HttpGetApListInfo(null);
                                    loginfo[0].success = "module_operate_success";
                                    loginfo[0].msg = "ap_log_success";
                                    lockScreen.unlock();
                                } else {
                                    toastr.info($translate.instant("failedAp"), '');
                                    loginfo[0].success = "module_operate_failure";
                                    loginfo[0].msg = "ap_log_error_1";
                                    lockScreen.unlock();
                                }
                                operationLog.setLog(operatorMsg, loginfo);
                            }, function() {
                                toastr.info($translate.instant("failedServer"), '');
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = 'failedServer';
                                operationLog.setLog(operatorMsg, loginfo);
                                lockScreen.unlock();
                            });
                        }
                    }
                });
                //bootbox.confirm($translate.instant("joingAp"), function(result) {
                //    if(result) {
                //        lockScreen.lock();
                //        var operatorMsg = "ap_access_group_name";
                //        var loginfo = [{
                //            'ip':"PVC",
                //            'success':"module_operate_failure",
                //            'msg':''}];
                //        authentifiedRequest.put("/toauth", null, bodyParas, function(response) {
                //            if (response != null && response.success) {
                //                toastr.info($translate.instant("successfullyAp"), '');
                //                APService.HttpGetApListInfo(null);
                //                loginfo[0].success = "module_operate_success";
                //                loginfo[0].msg = "ap_log_success";
                //                lockScreen.unlock();
                //            } else {
                //                toastr.info($translate.instant("failedAp"), '');
                //                loginfo[0].success = "module_operate_failure";
                //                loginfo[0].msg = "ap_log_error_1";
                //                lockScreen.unlock();
                //            }
                //            operationLog.setLog(operatorMsg, loginfo);
                //        }, function() {
                //            toastr.info($translate.instant("failedServer"), '');
                //            loginfo[0].success = "module_operate_failure";
                //            loginfo[0].msg = 'failedServer';
                //            operationLog.setLog(operatorMsg, loginfo);
                //            lockScreen.unlock();
                //        });
                //    }
                //});
            }else{
                toastr.warning($translate.instant("apgroupFull"), '');
            }
        };

        $scope.ShowLedOperate = function(item) {
            item.ledshow = !item.ledshow;
            if(item.ledshow){
                var url = url_pro + item.ip + url_port+"/ledstatus";
                authentifiedRequest.get(url, null, function(response){
                    if(response != null && response.success){
                        switch(response.result){
                            case 0:
                                item.operate = {"open": false, "off": true, "blink": false};
                                break;
                            case 1:
                                item.operate = {"open": true, "off": false, "blink": false};
                                break;
                            case 2:
                                item.operate = {"open": false, "off": false, "blink": true};
                                break;
                        }
                    }
                }, function(){});
            }
        }

        $scope.LedOperate = function(item, type) {
            var bodyParas = {
                "type": type
            };
            var confirm="";
            switch(type){
                case 100:
                    confirm=$translate.instant("locateAp");
                    break;
                case 101:
                    confirm=$translate.instant("restoreAp");
                    break;
                case 102:
                    confirm= $translate.instant("onLedAp");
                    break;
                case 103:
                    confirm=$translate.instant("offLedAp");
                    break;
            }
            var url = url_pro + item.ip + url_port +"/ledControl";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: confirm,
                callback: function(result) {
                    if(result) {
                        lockScreen.lock();
                        var operatorMsg = "set_led_status_log_name";
                        var loginfo = [{
                            'ip':item.ip,
                            'success':"module_operate_failure",
                            'msg':''}];
                        authentifiedRequest.put(url, null, bodyParas, function(response) {
                            if (response != null && response.success) {
                                switch(type){
                                    case 100:
                                        item.operate = {"open": false, "off": false, "blink": true};
                                        break;
                                    case 101:
                                        item.operate = {"open": true, "off": false, "blink": false};
                                        break;
                                    case 102:
                                        item.operate = {"open": true, "off": false, "blink": false};
                                        break;
                                    case 103:
                                        item.operate = {"open": false, "off": true, "blink": false};
                                        break;
                                }
                                loginfo[0].success = "module_operate_success";
                                loginfo[0].msg = 'ap_log_success';
                                lockScreen.unlock();
                            } else {
                                toastr.warning($translate.instant("setApLedF"), '');
                                loginfo[0].success = "module_operate_failure";
                                loginfo[0].msg = "ap_log_error_1";
                                lockScreen.unlock();
                            }
                            operationLog.setLog(operatorMsg, loginfo);
                        }, function() {
                            toastr.warning($translate.instant("failedServer"), '');
                            loginfo[0].success = "module_operate_failure";
                            loginfo[0].msg = 'failedServer';
                            operationLog.setLog(operatorMsg, loginfo);
                            lockScreen.unlock();
                        });
                    }
                }
            });
            //bootbox.confirm(confirm, function(result) {
            //    if(result) {
            //        lockScreen.lock();
            //        var operatorMsg = "set_led_status_log_name";
            //        var loginfo = [{
            //            'ip':item.ip,
            //            'success':"module_operate_failure",
            //            'msg':''}];
            //        authentifiedRequest.put(url, null, bodyParas, function(response) {
            //            if (response != null && response.success) {
            //                switch(type){
            //                    case 100:
            //                        item.operate = {"open": false, "off": false, "blink": true};
            //                        break;
            //                    case 101:
            //                        item.operate = {"open": true, "off": false, "blink": false};
            //                        break;
            //                    case 102:
            //                        item.operate = {"open": true, "off": false, "blink": false};
            //                        break;
            //                    case 103:
            //                        item.operate = {"open": false, "off": true, "blink": false};
            //                        break;
            //                }
            //                loginfo[0].success = "module_operate_success";
            //                loginfo[0].msg = 'ap_log_success';
            //                lockScreen.unlock();
            //            } else {
            //                toastr.warning($translate.instant("setApLedF"), '');
            //                loginfo[0].success = "module_operate_failure";
            //                loginfo[0].msg = "ap_log_error_1";
            //                lockScreen.unlock();
            //            }
            //            operationLog.setLog(operatorMsg, loginfo);
            //        }, function() {
            //            toastr.warning($translate.instant("failedServer"), '');
            //            loginfo[0].success = "module_operate_failure";
            //            loginfo[0].msg = 'failedServer';
            //            operationLog.setLog(operatorMsg, loginfo);
            //            lockScreen.unlock();
            //        });
            //    }
            //});
        }

        /*$scope.$watch('InterService.aplistinfo', function(newVal, oldVal) {
            if (newVal !== oldVal) {
                $scope.aps = InterService.getApListInfo();
                statisticApState();
            }
        }, true);*/

        $scope.$on('to-aplist-child', function(event,data) {
            $scope.aps = InterService.getApListInfo();
            statisticApState();
        });

        
        /**
         * showApMonitorData
         */
        $scope.showApMonitorData = function(item) {
            var title = $translate.instant("ClusterAP") + item.apname;
            var data = new Array();
            data['ip'] = item.ip;
            data['mac'] = item.mac;
            monitorService.changeObser('ap', data, title);
            $scope.clientManagement.changeClient('ap', item);
        }

    }])
    .filter("apStatusFilter", [function() {
        var filterfun = function(value) {
            switch (value) {
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
    }]);