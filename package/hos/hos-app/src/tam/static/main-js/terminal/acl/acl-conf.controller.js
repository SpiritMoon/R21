/**
 * Created by shensf on 2016/3/24.
 */
angular.module("module.terminal.acl")
    .controller("TerminalAclConfController", ['$scope', '$http', '$modalInstance','$translate','authentifiedRequest', 'InterService', 'batchSyncConfig', 'toastr', function($scope, $http, $modalInstance, $translate, authentifiedRequest, InterService, batchSyncConfig, toastr) {
        $scope.skin = InterService.skin;
        $scope.InterService = InterService;

        // $scope.aps = InterService.getCanConfigAps();

        // $scope.$watch('InterService', function(newVal, oldVal) {
        //     if (newVal !== oldVal) {
        //         $scope.aps = InterService.getCanConfigAps();
        //     }
        // }, true);

        /**
         * 页面参数对象初始化
         */
        $scope.ACLDetailGroupList = [];
        $scope.defaultACLAction = "accept";
        $scope.aclDetail = false;
        $scope.aclEdit = false;
        $scope.aclAdd = false;
        $scope.isAddACL = false;
        $scope.isEditACL = false;
        $scope.ACLIPProtocal = ["ALL","TCP", "UDP", "ICMP"];
        $scope.ACLTarget = ["ACCEPT", "REJECT"];
        
        $scope.ACLDetailTemp = {
             "src_ip":"",
             "src_port":"",
             "dest_ip":"",
             "dest_port":"",
            "src_ip_flag":false,
            "src_port_flag":false,
            "dest_ip_flag":false,
            "dest_port_flag":false,
             "proto":"",
             "target":""
        };

        $scope.ACLDetailCopy = {};
        $scope.ShowEditACL = function(currentDetail){
            $scope.aclDetail = false;
            $scope.aclEdit = true;
            $scope.aclAdd = false;
            $scope.oldAclDemo = angular.copy(currentDetail);
            $scope.ACLDetailTemp = angular.copy(currentDetail);
            $scope.ACLDetailCopy = angular.copy($scope.ACLDetailTemp);
            $scope.anycheck($scope.ACLDetailTemp);
        };

        $scope.ShowAclDetail = function(selectACL){
            $scope.aclDetail = true;
            $scope.aclEdit = false;
            $scope.aclAdd = false;
            $scope.ACLDetailTemp = selectACL;
        };
        $scope.ShowAddACL = function(){
            $scope.ACLDetailTemp = {};
            $("form[name='addacl']")[0].reset();
            this.addacl.$setPristine();
            $scope.ACLDetailTemp.src_ip_flag = false;
            $scope.ACLDetailTemp.src_port_flag = false;
            $scope.ACLDetailTemp.dest_ip_flag = false;
            $scope.ACLDetailTemp.dest_port_flag = false;
            $scope.ACLDetailTemp.proto = "ALL";
            $scope.ACLDetailTemp.target = "ACCEPT";
            $scope.aclAdd = true;
            $scope.aclDetail = false;
            $scope.aclEdit = false;
        };

        $scope.aclGetDetailRule = function(){
            var params = {};
            var old_length = 0;
            if(null != $scope.ACLDetailGroupList){
                old_length = $scope.ACLDetailGroupList.length;
            }
            authentifiedRequest.get("/aclrule", params, function(data,  status){
                if(status == 200 && data != null && data.success){
                    $scope.ACLDetailGroupList = data.result;
                    if(null != $scope.ACLDetailGroupList){
                        $scope.aclDetail = true;
                        $scope.aclAdd = false;
                        $scope.aclEdit = false;
                        if($scope.tempindex>0 && $scope.isEditACL){
                            /*  if acl be edit,tempindex is not null*/
                            $scope.ACLDetailTemp = $scope.ACLDetailGroupList[$scope.tempindex];
                        } else if($scope.isAddACL == true){
                            var new_length = $scope.ACLDetailGroupList.length;
                            if(new_length > old_length){
                                $scope.ACLDetailTemp = $scope.ACLDetailGroupList[new_length-1];
                            }
                        } else if($scope.isEditACL == false && $scope.isAddACL == false){
                            //$scope.ACLDetailTemp = $scope.ACLDetailGroupList[0];
                            angular.copy($scope.ACLDetailGroupList[0],$scope.ACLDetailTemp);
                        }
                        for(var j=0; j<$scope.ACLDetailGroupList.length; j++){
                            if($scope.ACLDetailGroupList[j].src_ip=="Any"){
                                $scope.ACLDetailGroupList[j].src_ip_flag = true;
                            }
                            if($scope.ACLDetailGroupList[j].src_port=="Any"){
                                $scope.ACLDetailGroupList[j].src_port_flag = true;
                            }
                            if($scope.ACLDetailGroupList[j].dest_ip=="Any"){
                                $scope.ACLDetailGroupList[j].dest_ip_flag = true;
                            }
                            if($scope.ACLDetailGroupList[j].dest_port=="Any"){
                                $scope.ACLDetailGroupList[j].dest_port_flag = true;
                            }
                        }
                    }
                    else{
                        $scope.aclDetail = false;
                    }
                }
            },function(){
            })

        };

        $scope.getDefaultACLAction = function(){
            var params = {};
            authentifiedRequest.get("/getdefaultACL", params, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.defaultACLAction = data.result;
                }
            },function(){
            })
        };

        $scope.setDefaultACLAction = function(defaultAction){
            $scope.defaultACLAction = defaultAction;
            var operatorMsg = 'access_set_acl_1';
            var requestParas = JSON.stringify($scope.defaultACLAction);
            batchSyncConfig.request("put", "/setdefaultACL", null, requestParas, function(){
                $scope.getDefaultACLAction();
            },null, operatorMsg);
        };
        $scope.DelACL = function(selectACL){
            var operatorMsg = 'access_del_acl_1';
            var url = "/deleterule/" + selectACL.rule;
            /*var confirm_tip = "Do you confirm to delete this acl rule?";*/
            var confirm_tip = $translate.instant("access_del_acl_2");
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
                        batchSyncConfig.request("delete", url, null, null, function(){
                            $scope.aclGetDetailRule();
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        batchSyncConfig.request("delete", url, null, null, function(){
            //            $scope.aclGetDetailRule();
            //        },null, operatorMsg);
            //    }
            //})
        };
       
        $scope.filterDuplicateObject = function(array, acltemp) {
            var temp = false;
            var status = false;
            //var tempobj = acltemp;
            var tempobj = angular.copy(acltemp);
               
            //add the key acltemp is not
            status = tempobj.hasOwnProperty('src_ip');
            if(false == status || tempobj.src_ip == ""){
                //tempobj.src_ip = "";
                tempobj.src_ip = "Any";
            }

            status = tempobj.hasOwnProperty('src_port');
            if(false == status || tempobj.src_port == ""){
                //tempobj.src_port = "";
                tempobj.src_port = "Any";
            }

            status = tempobj.hasOwnProperty('dest_ip');
            if(false == status || tempobj.dest_ip == ""){
                //tempobj.dest_ip = "";
                tempobj.dest_ip = "Any";
            }

            status = tempobj.hasOwnProperty('dest_port');
            if(false == status || tempobj.dest_port == ""){
                //tempobj.dest_port = "";
                tempobj.dest_port = "Any";
            }
         
            //compare key and value
            $.each(array,function(i,val){
                if((val.src_ip == tempobj.src_ip) && 
                    (val.src_port == tempobj.src_port) &&
                    (val.dest_ip == tempobj.dest_ip) &&
                    (val.dest_port == tempobj.dest_port) &&
                    (val.proto == tempobj.proto) &&
                    (val.target == tempobj.target)){
                        temp = true;
                        return false;
                }
            });
            
            return temp;
        }

        $scope.AddACL = function(){
            var operatorMsg = 'access_add_acl_1';
            $scope.isEditACL = false;
            $scope.isAddACL = true;

            if(null != $scope.ACLDetailGroupList){
                if($scope.ACLDetailGroupList.length >= 128){
                    /*toastr.info('ACL rules already pass 128!', '');*/
                    toastr.info($translate.instant("access_add_acl_2"), '');
                    return ;
                }
                var index = $scope.filterDuplicateObject($scope.ACLDetailGroupList, $scope.ACLDetailTemp);
                if(true == index){
                    toastr.info($translate.instant("access_add_acl_3"), '');
                    return ;
                }
            }
            var requestParas = JSON.stringify($scope.ACLDetailTemp);
            batchSyncConfig.request("put", "/addfirewall", null, requestParas, function(){
                $scope.aclGetDetailRule();
               // $scope.Cancel();
                $scope.ACLDetailTemp={};
            },null, operatorMsg);
        };
        $scope.anycheck = function(acl){
            if("Any" == acl.src_ip){
                acl.src_ip = "";
                acl.src_ip_flag = true;
            }else{
                acl.src_ip_flag = false;
            }
            if("Any" == acl.src_port){
                acl.src_port = "";
                acl.src_port_flag = true;
            }else{
                acl.src_port_flag = false;
            }
            if("Any" == acl.dest_ip){
                acl.dest_ip = "";
                acl.dest_ip_flag = true;
            }else{
                acl.dest_ip_flag = false;
            }
            if("Any" == acl.dest_port){
                acl.dest_port = "";
                acl.dest_port_flag = true;
            }else{
                acl.dest_port_flag = false;
            }
        };

        $scope.check_src_ip = function(){
            if($scope.ACLDetailTemp.src_ip_flag == true){
                $scope.ACLDetailTemp.src_ip = "";
            }else{
                $scope.ACLDetailTemp.src_ip = $scope.ACLDetailCopy.src_ip;
            }
        }

        $scope.check_src_port = function(){
            if($scope.ACLDetailTemp.src_port_flag == true){
                $scope.ACLDetailTemp.src_port = "";
            }else{
                $scope.ACLDetailTemp.src_port = $scope.ACLDetailCopy.src_port;
            }
        }
        $scope.check_dest_ip = function(){
            if($scope.ACLDetailTemp.dest_ip_flag == true){
                $scope.ACLDetailTemp.dest_ip = "";
            }else{
                $scope.ACLDetailTemp.dest_ip = $scope.ACLDetailCopy.dest_ip;
            }
        }
        $scope.check_dest_port = function(){
            if($scope.ACLDetailTemp.dest_port_flag == true){
                $scope.ACLDetailTemp.dest_port = "";
            }else{
                $scope.ACLDetailTemp.dest_port = $scope.ACLDetailCopy.dest_port;
            }
        }

        $scope.EditACL = function(){
           /* var operatorMsg = 'Modify ACL rule';*/
            var operatorMsg = 'access_set_acl_2';
            $scope.isAddACL = false;
            $scope.isEditACL = true;
            var aclArray = [];
            aclArray.push($scope.oldAclDemo);
            if($scope.filterDuplicateObject(aclArray, $scope.ACLDetailTemp)){
                //src_ip,src_port des_ip,des_port are same
            }else{
                var index = $scope.filterDuplicateObject($scope.ACLDetailGroupList, $scope.ACLDetailTemp);
                if(true == index){
                    toastr.info($translate.instant("access_add_acl_3"), '');
                    return ;
                }
            }
            var requestParas = JSON.stringify($scope.ACLDetailTemp);
            $scope.tempindex= $.inArray($scope.ACLDetailTemp,$scope.ACLDetailGroupList);
            batchSyncConfig.request("put", "/modifyfirewall", null, requestParas, function(){
                $scope.aclGetDetailRule();
                //$scope.Cancel();
            },null, operatorMsg);
        }

        /**
         * �رհ�ť
         */
        $scope.close = function() {
            $modalInstance.close();
        };
        $scope.Cancel = function() {
            $scope.aclAdd = false;
            $scope.aclDetail = false;
            $scope.aclEdit = false;
        };


        $scope.moveACLlist = function(acla, aclb){
            /*var operatorMsg = 'Move ACL rule';*/
            var operatorMsg = 'access_set_acl_3';
            var moveacl = [];
            $scope.anycheck(acla);
            $scope.anycheck(aclb);
            moveacl.push(acla);
            moveacl.push(aclb);
            var requestParas = JSON.stringify(moveacl);
            batchSyncConfig.request("put", "/moveACLlist", null, requestParas, function(){
                $scope.aclGetDetailRule();
            },null,operatorMsg);
        }

        $scope.Moveup = function(index){
            $scope.temp = "";
            $scope.temp = $scope.ACLDetailGroupList[index-1];
            $scope.ACLDetailGroupList[index-1] = $scope.ACLDetailGroupList[index];
            $scope.ACLDetailGroupList[index] = $scope.temp;
            $scope.temp = "";
            var temp1 = $scope.ACLDetailGroupList[index];
            var temp2 = $scope.ACLDetailGroupList[index-1];
            $scope.moveACLlist(temp1, temp2);
        };

        $scope.Movedown = function(index){
            $scope.temp = $scope.ACLDetailGroupList[index+1];
            $scope.ACLDetailGroupList[index+1] = $scope.ACLDetailGroupList[index];
            $scope.ACLDetailGroupList[index] = $scope.temp;
            $scope.temp = "";
            var temp1 = $scope.ACLDetailGroupList[index];
            var temp2 = $scope.ACLDetailGroupList[index+1];
            $scope.moveACLlist(temp1, temp2);
 
        };

        /**
         *
         *
         */
        $scope.aclGetDetailRule();
        $scope.getDefaultACLAction();
    }])
;