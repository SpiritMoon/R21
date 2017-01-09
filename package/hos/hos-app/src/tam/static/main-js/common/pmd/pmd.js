angular.module('common')
    .controller("pmdContronller", ['$scope', '$modalInstance', '$translate','$modal', 'InterService','authentifiedRequest','toastr','batchSyncConfig', function($scope, $modalInstance,$translate, $modal, InterService,authentifiedRequest,toastr,batchSyncConfig) {
        $scope.skin = InterService.skin;
        $scope.InterService = InterService;
        $scope.userName = window.localStorage.username;


        $scope.pmdInformation = {pmdSwitch:true,tftpServer:""};
        var data = {enable:true,pmdIp:""};
        getInitpmdSwitch();
        getInitpmdIP();
        function getInitpmdSwitch (){
            authentifiedRequest.get("/other/pmdSwitch", null, function(response) {
                if (response != null && response.success) {
                    if(response.result == '1'){
                        $scope.pmdInformation.pmdSwitch = true;
                    }else $scope.pmdInformation.pmdSwitch = false;
                }
            }, function() { //error

            });

        }
        function getInitpmdIP (){
            authentifiedRequest.get("/other/pmdIp", null, function(response) {
                if (response != null && response.success) {
                    $scope.pmdInformation.tftpServer = response.result;
                }
            }, function() { //error

            });

        }

        //config switch
        $scope.configStatus = function () {
            console.info($scope.pmdInformation.pmdSwitch);
            data.enable = $scope.pmdInformation.pmdSwitch;
            batchSyncConfig.request("put", "/other/setPmdSwitch", null, data, function(response) {
                if(response != null && response.success){
                    
                }else{
					
		}
            },null,null);
        }

        //config tftp server ip
        $scope.savePmd = function () {
            console.info($scope.pmdInformation.tftpServer);
            data.pmdIp = $scope.pmdInformation.tftpServer;
            batchSyncConfig.request("put", "/other/setPmdIp", null, data, function(response) {
                if(response != null && response.success){
                    
                }else{
		    
		}
            },null,null);
        }

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
