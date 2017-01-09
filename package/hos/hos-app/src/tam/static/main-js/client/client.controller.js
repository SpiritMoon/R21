/**
 * Created by shensf on 2016/3/25.
 */
angular.module("module.client", [])
    .filter("clientOwnerName", [function(){
        var filterFun = function(value){
            if(value=="ap"){
                return "AP";
            }else if(value=="wlan"){
                return "WLAN";
            }else if(value=="cluster"){
                return "Group";
            }else{
                return "";
            }
        }
        return filterFun;
    }])
    .controller("ClientController", ['$scope', 'batchSyncConfig', 'clientService', 'monitorService', 'singleModal','$translate', function($scope, batchSyncConfig, clientService, monitorService, singleModal,$translate) {

        $scope.clientList = [];
        $scope.clientNum = 0;
        $scope.divWidth="";
        $scope.flag = 'cluster';
        $scope.clientOwner = "";
        $scope.currentName = "";
        $scope.currentMac = "";
        $scope.clientManagement.changeClient = function(info, data){

            if(info == 'ap'){
                $scope.flag = 'ap';
                if(data.hasOwnProperty('apname')){
                    $scope.clientOwner = data.apname;
                    $scope.currentMac = data.mac;
                    $scope.currentName = data.apname;

                }else{
                    $scope.clientOwner = data;
                }
                $scope.clientList = clientService.getApClient($scope.currentMac);
            }else if(info == 'wlan'){
                $scope.flag = 'wlan';
                 $scope.clientOwner = data;
                $scope.clientList = clientService.getWlanClient(data);
            }else {
                $scope.flag = 'cluster';
                $scope.clientOwner = data;
                $scope.clientList = clientService.getClientList();
            }
            if(0 < $scope.clientList.length){
                $scope.clientNum = $scope.clientList.length;
                if(4 < $scope.clientNum){
                    $scope.divWidth="padding-right:17px;";
                }else{
                    $scope.divWidth="";
                }
            }else{
                $scope.clientNum = 0;
                $scope.clientList = [];
                $scope.divWidth="";
            }
        }

        $scope.clientManagement.query = function(clientCallback) {
            batchSyncConfig.getAll("/totalclientlist", null, function(results) {
                // if(0 < results.length){
                //     $scope.clientList = results;
                //     $scope.clientNum = results.length;
                //     if(4 < results.length){
                //         $scope.divWidth="padding-right:17px;";
                //     }else{
                //         $scope.divWidth="";
                //     }
                // }else{
                //     $scope.clientNum = 0;
                //     $scope.clientList = [];
                //     $scope.divWidth="";
                // }
				if(0 < results.length){
					clientService.setClientList(results);
				}
               $scope.clientManagement.changeClient($scope.flag, $scope.clientOwner);
               // $scope.clientManagement.changeClient($scope.flag, '');
                clientCallback();
            });

        }

        $scope.clientManagement.query($scope.clientCallback);
        /**
         *
         */
        $scope.openClientPageInit = function() {
                singleModal.open({
                    templateUrl: 'client/client-detail.html',
                    controller: 'ClientDetailController',
                    size: 'lg',
                    backdrop: true
                },function(result){
                     $scope.clientManagement.query($scope.clientCallback);
                },function(reason){
                     $scope.clientManagement.query($scope.clientCallback);
                });
        };

        /**
         * 进行client monitor信息展示
         */
        $scope.showClientMonitor = function(item) {
            var title = $translate.instant("ClusterClient") + item.UserMAC;
            monitorService.changeObser('client', item.UserMAC, title);
        }
    }]);