angular.module('common')
    .controller("toolsContronller", ['$scope', '$modalInstance', '$translate','$modal', 'InterService','authentifiedRequest','toastr','batchSyncConfig', function($scope, $modalInstance,$translate, $modal, InterService,authentifiedRequest,toastr,batchSyncConfig) {
        $scope.skin = InterService.skin;
        $scope.InterService = InterService;

        $scope.showsysinfo_flag = false;
        $scope.other_command_flag = true;
        //tools
        $scope.tools = [{
            "id": 0,
            "name": '-'+$translate.instant("Select Command")+'-'
        }, {
            "id": 1,
            "name": "show system health"
        }, {
            "id": 2,
            "name": "show WIFI info"
        },
        // {
        //     "id": 3,
        //     "name": "show traps info"
        // }, 
        {
            "id": 4,
            "name": "show history syslog info"
        },
        //    {
        //    "id": 7,
        //    "name": "tcpdump"
        //},
            {
            "id": 8,
            "name": "traceroute"
        }, {
            "id": 9,
            "name": "ping"
        }, {
            "id": 10,
            "name": "show history reset reason"
        }];

        //operation
        $scope.operation = {};

        //selectApIp
        $scope.operation.selectApIp = {};

        $scope.aps = [];

        $scope.requestParams = {
            'command': 0,//id
            'hostname': ''//hostname
        };

        //show hostname flag
        $scope.showHostname = false;

        //result
        $scope.operation.result = '';

        $scope.initFuc = function() {
            $scope.aps = InterService.getCanConfigAps();
            for(var i =0;i<$scope.aps.length; i++){
                if($scope.aps[i].role == 1){
                    $scope.operation.selectApIp = $scope.aps[i];
                }
            }
        };

        $scope.initFuc();


        //change tool
        $scope.changeTool = function() {
            //traceroute ping need showHostname
            
            var tem = $scope.requestParams.command;
            if(tem == 8 || tem == 9){
                $scope.showHostname = true;
                return;
            }

            $scope.showHostname = false;
            $scope.requestParams.hostname = '';

        };

        //tools exec
        $scope.exec = function(){

            //check
            if($scope.operation.selectApIp.ip == ''){
                toastr.warning( $translate.instant("pleaseSelectAp"));
                return;
            }

            if($scope.requestParams.command == 0){
                toastr.warning($translate.instant("pleaseSelectTool"));
                return;
            }

            var tem = $scope.requestParams.command;
            if((tem == 8 || tem == 9) && $scope.requestParams.hostname == ''){
                toastr.warning($translate.instant("hostnameNotAllowEmpty"));
                return;
            }
            
            $scope.operation.result = '';
			
			//var scheme = 'http://';
			var scheme = InterService.getProtocol()+"://";
            //var port = ':8080';
            var port = ":"+InterService.getPort();
            var url = scheme + $scope.operation.selectApIp.ip + port + "/other/tools";
            var timeout = '30000';//30s
            authentifiedRequest.request('post', url, null, $scope.requestParams, timeout, function(data){
                if(data != null && data.success){
                    $scope.operation.result = data.result;

                    $scope.showsysinfo = {
                        "free": [],
                        "df": []
                    };
                    $scope.sysinfo_result = {
                        lineOne: "",
                        lineTwo: "",
                        lineThree: "",
                        lineFour: "",
                        lineFive: "",
                        lineSix:""
                    };
                    //show system health result realign in page
                    if($scope.requestParams.command == 1){
                        $scope.showsysinfo_flag = true;
                        $scope.other_command_flag = false;
                        var lines = $scope.operation.result.split("\r\n"); //
                        //$scope.sysinfo_result = {};

                        for(var i = 0; i < lines.length; i++){
                            if(i < 4){
                               var free_line = lines[i].replace(/[ ]+/g, "#");
                               var free_line_arr = free_line.split("#");
                               if(free_line_arr[0]=="" || free_line_arr[0] == "Mem:"){
                                    $scope.sysinfo_result = {};
                                    $scope.sysinfo_result.lineOne = free_line_arr[0];
                                    $scope.sysinfo_result.lineTwo = free_line_arr[1];
                                    $scope.sysinfo_result.lineThree = free_line_arr[2];
                                    $scope.sysinfo_result.lineFour = free_line_arr[3];
                                    $scope.sysinfo_result.lineFive = free_line_arr[4];
                                    $scope.sysinfo_result.lineSix = free_line_arr[5];
                                    $scope.showsysinfo.free.push($scope.sysinfo_result);
                                    $scope.sysinfo_result = {};
                               }
                               else if(free_line_arr[0] == "-/+"){
                                    $scope.sysinfo_result = {};
                                    free_line_arr[0] = free_line_arr[0]  + " " + free_line_arr[1];
                                    $scope.sysinfo_result.lineOne = free_line_arr[0];
                                    $scope.sysinfo_result.lineTwo = free_line_arr[2];
                                    $scope.sysinfo_result.lineThree = free_line_arr[3];
                                    $scope.sysinfo_result.lineFour = " ";
                                    $scope.sysinfo_result.lineFive = " ";
                                    $scope.sysinfo_result.lineSix = " ";
                                    $scope.showsysinfo.free.push($scope.sysinfo_result);
                                    $scope.sysinfo_result = {};

                               }else if(free_line_arr[0] == "Swap:"){
                                    $scope.sysinfo_result = {};
                                    $scope.sysinfo_result.lineOne = free_line_arr[0];
                                    $scope.sysinfo_result.lineTwo = free_line_arr[1];
                                    $scope.sysinfo_result.lineThree = free_line_arr[2];
                                    $scope.sysinfo_result.lineFour = free_line_arr[3];
                                    $scope.sysinfo_result.lineFive = " ";
                                    $scope.sysinfo_result.lineSix = " ";
                                    $scope.showsysinfo.free.push($scope.sysinfo_result);
                                    $scope.sysinfo_result = {};
                               }
                            }else{
                                var each_line = lines[i].replace(/[ ]+/g, "#");//replace spaces to #
                                var each_line_arr = each_line.split("#");
                                if(each_line_arr[5] == "Mounted"){
                                    each_line_arr[5] = "Mounted on";
                                }
                                $scope.sysinfo_result.lineOne = each_line_arr[0];
                                $scope.sysinfo_result.lineTwo = each_line_arr[1];
                                $scope.sysinfo_result.lineThree = each_line_arr[2];
                                $scope.sysinfo_result.lineFour = each_line_arr[3];
                                $scope.sysinfo_result.lineFive = each_line_arr[4];
                                $scope.sysinfo_result.lineSix = each_line_arr[5];
                                $scope.showsysinfo.df.push($scope.sysinfo_result);
                                $scope.sysinfo_result = {};
                            }
                        }
                    }
                    else{
                        $scope.showsysinfo_flag = false;
                        $scope.other_command_flag = true;
                    }
                   
                }else{

                    var msg = $translate.instant('Operate')+' '+$translate.instant('module_operate_failure');
                    //module_operate_success
                    $scope.operation.result = msg;
                }
                
            }, function(){
                var msg = $translate.instant('Operate')+' '+$translate.instant('module_operate_failure');
                $scope.operation.result = msg;
            });
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };




        //pmd controller
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
    }]);