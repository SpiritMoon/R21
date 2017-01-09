angular.module("module.terminal.authentication",[])
    .controller('TerminalAuthViewController',['$scope', 'singleModal','authentifiedRequest', 'InterService', 'batchSyncConfig', function($scope, singleModal,authentifiedRequest, InterService, batchSyncConfig){
        $scope.InterService = InterService;
        $scope.aps = InterService.getCanConfigAps();

        $scope.$watch('InterService', function(newVal, oldVal) {
            if (newVal !== oldVal) {
                $scope.aps = InterService.getCanConfigAps();
            }
        }, true);

        $scope.Auth={
            "type" : "device"
        };
        $scope.deviceType=[];
        $scope.osType=[];

        $scope.xFunction = function(){
            return function(d) {
                return d.key;
            };
        }
        $scope.yFunction = function(){
            return function(d) {
                return d.y;
            };
        }

        $scope.toggleManager.getauthinfo = function() {
            $scope.deviceType=[];
            $scope.osType=[];
            batchSyncConfig.getAll("/authclientinfo", null, function(results) {
                var i = 0;

                $scope.tempdev=[
                { key: "iPhone", y: 0 }, 
                { key: "iPad", y: 0 }, 
                { key: "Mobile", y: 0 }, 
                { key: "PC", y: 0 }, 
                { key: "Mac PC", y: 0 },
                { key: "unknown", y: 0 }];

                $scope.tempos=[
                { key: "IOS", y: 0 }, 
                { key: "Android", y:0},
                { key: "BlackBerry", y: 0 }, 
                { key: "Mac OS", y:0},
                { key: "Windows ME", y: 0 },
                { key: "Windows Server", y: 0 }, 
                { key: "Windows Vista", y: 0 },
                { key: "Windows XP", y: 0 }, 
                { key: "Windows 7", y: 0 }, 
                { key: "Windows 8", y: 0 }, 
                { key: "Windows 10", y: 0 }, 
                { key: "Linux", y : 0},
                { key: "unknown",y : 0}];

                for(i=0; i< results.length; i++){
                    for(var j = 0; j < results[i].length; j++){
                        if(j < 6){
                            if("devUnknown" == results[i][j].key){
                                $scope.tempdev[5].y += results[i][j].y;
                            }else if($scope.tempdev[j].key == results[i][j].key){
                                $scope.tempdev[j].y += results[i][j].y;
                            }
                        }else {
                            if($scope.tempos[j - 6].key == results[i][j].key){
                                $scope.tempos[j - 6].y += results[i][j].y;
                            }
                        }
                    }
                }
                for(i = 0; i < $scope.tempdev.length;i++){
                    if($scope.tempdev[i].y){
                        $scope.deviceType = $scope.tempdev;
                        break;
                    }
                }
                for(i = 0; i < $scope.tempos.length; i++){
                    if($scope.tempos[i].y){
                        $scope.osType = $scope.tempos;
                        break;
                    }
                }
            });
        }


        $scope.toggleManager.AuthViewInit = function(){
            
        };

        /**
         *
         */
        $scope.openAuthenticationViewPageInit = function(){
            singleModal.open({
                templateUrl: 'terminal/authentication/authentication-conf.html',
                controller: 'TerminalAuthConfController',
                size:'lg',
                backdrop:true
            },function(result) {
                $scope.toggleManager.getauthinfo();
            },function(reason) {
                $scope.toggleManager.AuthViewInit();
            });

        };

        //Pop up authentication configuration after GuestOperator signed in
        if(window.localStorage.username == "GuestOperator"){
            window.localStorage.isFromLogin++;
            $scope.openAuthenticationViewPageInit();
        }
    }])
;
