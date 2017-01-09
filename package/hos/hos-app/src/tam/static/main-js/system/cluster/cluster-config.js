angular.module("system")
    .controller("clusterConfController", ['$scope','$modal','$modalInstance','$translate','authentifiedRequest','InterService','ClusterService','batchSyncConfig','lockScreen', 'operationLog', function($scope,$modal,$modalInstance,$translate,authentifiedRequest,InterService,ClusterService,batchSyncConfig,lockScreen, operationLog) {
        $scope.skin = InterService.skin;
	    $scope.InterService = InterService;
        $scope.accountInfo={"admin":"","viewerstatus":"0","view":"","gueststatus":"0","guest":""};
        $scope.subInfo={"admin":"","viewerstatus":"0","view":"","gueststatus":"0","guest":""};
        $scope.accountconfirm={"adminconfirm":"","viewconfirm":"","guestconfirm":""};
        $scope.cluster_conf={"cluster_id":0,"cluster_name":"","cluster_location":"","cluster_vip":"","cluster_netmask":""};

        function httpget(){
            lockScreen.lock();
            ClusterService.HttpClusterInfo(function(){
                getClusterInfo();
            });
        }
        function getClusterInfo(){
            $scope.clusterinfo = ClusterService.getClusterinfoSer();
            $scope.cluster_conf.cluster_id= parseInt($scope.clusterinfo.cluster_id);
            $scope.cluster_conf.cluster_name= $scope.clusterinfo.cluster_name;
            $scope.cluster_conf.cluster_location= $scope.clusterinfo.cluster_location;
            $scope.cluster_conf.cluster_vip= $scope.clusterinfo.cluster_vip;
            $scope.cluster_conf.cluster_netmask= $scope.clusterinfo.cluster_netmask;
            $scope.accountInfo.viewerstatus = $scope.clusterinfo.Viewer;
            $scope.accountInfo.gueststatus = $scope.clusterinfo.GuestOperator;
            lockScreen.unlock();
        };
        httpget();
        $scope.exchange = function(type){
            if(type ==100){
                $scope.accountInfo.view="";
                $scope.accountconfirm.viewconfirm="";
            }else if(type == 200){
                $scope.accountInfo.guest="";
                $scope.accountconfirm.guestconfirm="";
            }
        };

        $scope.saveGroupID = function(){
            var operatorMsg = "modify_cluster_id";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("modify_cluster_id_confirm"),
                callback: function(result) {
                    if (result) {
                        batchSyncConfig.request("put","/editclusterid",null,$scope.cluster_conf, function(){

                            httpget();
                        },null,operatorMsg);
                        //logout
                        authentifiedRequest.post('/authentication/logout', null, null, function(data){
                            // must return
                            window.location.href = "/static/login.html";
                        });
                    }
                    else{
                        $scope.cluster_conf.cluster_id= parseInt($scope.clusterinfo.cluster_id);
                    }
                }
            });
            //bootbox.confirm($translate.instant("modify_cluster_id_confirm"), function(result) {
            //    if (result) {
            //        batchSyncConfig.request("put","/editclusterid",null,$scope.cluster_conf, function(){
            //
            //            httpget();
            //        },null,operatorMsg);
            //        //logout
            //        authentifiedRequest.post('/authentication/logout', null, null, function(data){
            //            // must return
            //            window.location.href = "/static/login.html";
            //        });
            //    }
            //    else{
            //        $scope.cluster_conf.cluster_id= parseInt($scope.clusterinfo.cluster_id);
            //    }
            //});
            $scope.cancel();
        };

        $scope.Clusterinfo = function(){
            var pvcinfo = InterService.getPVCinfo();
            var url="";
            if(pvcinfo==null||pvcinfo==''){
                toastr.warning($translate.instant("cannot_get_pvc_info"));
                return;
            }else{
                url = InterService.getProtocol()+"://" + pvcinfo + ":"+InterService.getPort()+"/editvip";
                //url = "http://" + pvcinfo + ":8080/editvip";
            }

            var operatorMsg = "modify_cluster_baseinfo_log_name";
            batchSyncConfig.request("put","/editclusterinfo",null,$scope.cluster_conf, function(){
                httpget();
            },null, operatorMsg);


            var operatorMsg1 = "modify_cluster_vip";
            var loginfo = [{
                'ip':"PVC",
                'success':"module_oprate_failure",
                'msg':''}];
            authentifiedRequest.put(url, null, $scope.cluster_conf, function(response){
                if(response != null && response.success){
                    loginfo[0].success = "module_operate_success";
                    loginfo[0].msg = "ap_log_success";
                }else{
                    loginfo[0].success = "module_oprate_failure";
                    loginfo[0].msg = "ap_log_error_1";
                    toastr.warning($translate.instant("modify_cluster_vip_failed"));
                }
                operationLog.setLog(operatorMsg1, loginfo);
            }, function(){
                loginfo[0].success = "module_oprate_failure";
                loginfo[0].msg = 'failedServer';
                operationLog.setLog(operatorMsg1, loginfo);
                toastr.warning($translate.instant("failedServer"));
            });
            $scope.cancel();
        }

        $scope.Accountinfo = function(){
            if($scope.accountInfo.admin.length > 0){
                $scope.subInfo.admin=hex_md5($scope.accountInfo.admin).toLowerCase ();
            }
            if($scope.accountInfo.view.length > 0){
                $scope.subInfo.view=hex_md5($scope.accountInfo.view).toLowerCase ();
            }
            if($scope.accountInfo.guest.length > 0){
                $scope.subInfo.guest=hex_md5($scope.accountInfo.guest).toLowerCase ();
            }
            $scope.subInfo.viewerstatus=$scope.accountInfo.viewerstatus;
            $scope.subInfo.gueststatus=$scope.accountInfo.gueststatus;
            var operatorMsg = "modify_user_info_log_name";
            batchSyncConfig.request("put","/editpasswd",null,$scope.subInfo,function(){
                $scope.accountInfo={"admin":"","viewerstatus":"0","view":"","gueststatus":"0","guest":""};
                $scope.accountconfirm={"adminconfirm":"","viewconfirm":"","guestconfirm":""};
                //update administrator password will logout

                httpget();
                $scope.cancel();
            },null,operatorMsg);
            if($scope.accountInfo.admin.length > 0){
                console.info("-----------------------");
                authentifiedRequest.post('/authentication/logout', null, null, function(data){
                    // must return
                    window.location.href = "/static/login.html";
                });
            }
        }
        
        //cancel dosomething
        $scope.cancel = function() {
            $modalInstance.close();
        };

    }]);


