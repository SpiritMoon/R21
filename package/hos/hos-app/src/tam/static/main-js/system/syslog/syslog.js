angular.module('system')
    .controller("syslogContronller", ['$scope', 'InterService', 'authentifiedRequest', 'batchSyncConfig', 'lockScreen', '$http', 'operationLog', 'toastr', '$translate', function($scope, InterService, authentifiedRequest, batchSyncConfig, lockScreen, $http, operationLog, toastr, $translate) {
        $scope.InterService = InterService;

	    /**
         * syslog parameter init
         */
        /*$scope.syslogData = [
            {
                "key": "Error",
                "values": []
            },
            {
                "key": "Critical",
                "values": []
            },
            {
                "key": "Alert",
                "values": []
            },
            {
                "key": "Emerg",
                "values": []
            }
        ];*/
        $scope.syslogs = [];
        $scope.apInfo = [];

        $scope.syslogLevels = [
            { name: "Emergent", value: "LOG_EMERG"},
            { name: "Alert", value: "LOG_ALERT"},
            { name: "Critical", value: "LOG_CRIT"},
            { name: "Error", value: "LOG_ERR"},
            { name: "Warning", value: "LOG_WARNING"},
            { name: "Notice", value: "LOG_NOTICE"},
            { name: "Info", value: "LOG_INFO"},
            { name: "Debug/ALL", value: "LOG_DEBUG"}];

        $scope.syslogParmas = {};
        $scope.selectedLevel = $scope.syslogLevels[3];

        $scope.echoSyslogLevels = function(level) {
            if("LOG_DEBUG" == level){
                $scope.selectedLevel = $scope.syslogLevels[7];
            }else if("LOG_INFO" == level){
                $scope.selectedLevel = $scope.syslogLevels[6];
            }else if("LOG_NOTICE" == level){
                $scope.selectedLevel = $scope.syslogLevels[5];
            }else if("LOG_WARNING" == level){
                $scope.selectedLevel = $scope.syslogLevels[4];
            }else if("LOG_ERR" == level){
                $scope.selectedLevel = $scope.syslogLevels[3];
            }else if("LOG_CRIT" == level){
                $scope.selectedLevel = $scope.syslogLevels[2];
            }else if("LOG_ALERT" == level){
                $scope.selectedLevel = $scope.syslogLevels[1];
            }else if("LOG_EMERG" == level){
                $scope.selectedLevel = $scope.syslogLevels[0];
            }
        };

        /*$scope.xAxisTickFormatFunction = function(){
            return function(d){
                return d3.time.format('%H:%M')(moment.unix(d).toDate());
            }
        };*/

        /**
         * combination chart data
         */
        /*function getSyslogData(data){
            //alert(JSON.stringify(data));
            var errNum=0;
            var critNum=0;
            var alertNum=0;
            var emergNum=0;
            for(var i=0; i<data.length; i++){
                errNum += data[i].errSyslogNum;
                critNum += data[i].critSyslogNum;
                alertNum += data[i].alertSyslogNum;
                emergNum += data[i].emergSyslogNum;
            }

            $scope.temp = angular.copy($scope.syslogData);

            var now = Date.parse(new Date())/1000;
            var arrayLength  = $scope.temp[0].values.length;
            if(60 == arrayLength){
                $scope.temp[0].values.splice(0, 1);
                $scope.temp[1].values.splice(0, 1);
                $scope.temp[2].values.splice(0, 1);
                $scope.temp[3].values.splice(0, 1);
            }

            $scope.temp[0].values.push(new Array(now, errNum));
            $scope.temp[1].values.push(new Array(now, critNum));
            $scope.temp[2].values.push(new Array(now, alertNum));
            $scope.temp[3].values.push(new Array(now, emergNum));

            $scope.syslogData = angular.copy($scope.temp);
            //alert(JSON.stringify($scope.syslogData));
        }*/

        $scope.toggleManager.syslogInit = function(){
            $scope.syslogInfoQuery();
            $scope.syslogServerQuery();
            $scope.apInfoQuery();
        };

        /**
         * http request to obtain the configuration of syslog
         */
        $scope.syslogServerQuery = function(){
            var params ={};

            authentifiedRequest.get("/syslogServerPara", params, function(response, status){
                if(status == 200 && null != response && response.success){
                    $scope.syslogParmas = response.result;
                    $scope.echoSyslogLevels($scope.syslogParmas.level);
                }
            }, function(){
                //console.info('query syslog server parameter error!');
            });
        };

        $scope.apInfoQuery = function(){
            /**
             * get ap list
             */
            $scope.apInfo = InterService.getCanConfigAps();
            $scope.selectedAp = $scope.apInfo[0];
        };

        $scope.syslogInfoQuery = function(){
            var params ={};
            $scope.syslogs = [];
            /*var syslogStatistics = [];
            var updateTimes = 0;*/

            /**
             * get ap list
             */
            var apList = InterService.getCanConfigAps();

            for(var i=0; i<apList.length; i++){
                var host = apList[i].ip;
                //var url1 = "http://" + host + ":8080/syslog";
                var url1 = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/syslog";
                authentifiedRequest.get(url1, params, function(response, status){
                    if(status == 200 && null != response && response.success){
                        if($scope.syslogs.length == 0){
                            $scope.syslogs = angular.copy(response.result);
                        }else{
                            $scope.syslogs = $scope.syslogs.concat(response.result);
                        }
                    }
                }, function(){
                    //console.info('query syslog info error!');
                });

                /*var url2 = "http://" + host + ":8080/syslogStatistics";
                authentifiedRequest.get(url2, params, function(response, status){
                    if(status == 200 && null != response && response.success){
                        syslogStatistics.push(response.result);
                        updateTimes++;
                        if(updateTimes == apList.length){
                            getSyslogData(syslogStatistics);
                        }
                    }
                }, function(){
                    //console.info('query syslog statistics error!');
                });*/
            }
        };

        /**
         * config syslog server level
         */
        $scope.saveServerLevel = function () {
            $scope.syslogParmas.level = $scope.selectedLevel.value;
            var requestParas = JSON.stringify($scope.syslogParmas);
            var operatorMsg = "syslog_edit_level";
            var logtemp = $scope.syslogParmas.level;

            batchSyncConfig.request("put", "/syslogServerLevel", null, requestParas, function(){
                $scope.syslogServerQuery();
            }, null, operatorMsg, null, logtemp);
        };

        /**
         * config log remote switch
         */
        $scope.configLogRemote = function() {
            var requestParas = JSON.stringify($scope.syslogParmas);
            var operatorMsg;
            if($scope.syslogParmas.logRemoteSwitch){
                operatorMsg = "syslog_edit_remoteSwitch_1";
            }else{
                operatorMsg = "syslog_edit_remoteSwitch_2";
            }

            batchSyncConfig.request("put", "/logRemoteSwitch", null, requestParas, function(){
                $scope.syslogServerQuery();
            }, null, operatorMsg);
        };

        /**
         * config syslog server ip
         */
        $scope.saveServerIp = function () {
            var requestParas = JSON.stringify($scope.syslogParmas);
            var operatorMsg = "syslog_edit_serverIp";
            var logtemp = $scope.syslogParmas.ip;

            batchSyncConfig.request("put", "/syslogServerIp", null, requestParas, function(){
                $scope.syslogServerQuery();
            }, null, operatorMsg, null, logtemp);
        };

        function saveFile(data, headers, filename){
            var octetStreamMime = 'application/octet-stream';
            var success = false;
            headers = headers();
            var contentType = headers['content-type'] || octetStreamMime;
            try{
                //console.log("Trying saveBlob method ...");
                var blob = new Blob([data], { type: contentType });
                if(navigator.msSaveBlob) {
                    navigator.msSaveBlob(blob, filename);
                }else{
                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
                    if(saveBlob === undefined){
                        throw "Not supported";
                    }else{
                        saveBlob(blob, filename);
                    }
                    //console.log("saveBlob succeeded");
                    success = true;
                }
            }catch(ex){
                //console.log("saveBlob method failed with the following exception:");
                //console.log(ex);
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
                            //console.log(ex);
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
                        }catch(ex){
                            //console.log("Download link method with window.location failed with the following exception:");
                            //console.log(ex);
                        }
                    }
                }
            }
            if(!success){
                //console.log("No methods worked for saving the arraybuffer, using last resort window.open");
                window.open(httpPath, '_blank', '');
            }
        };

        /**
         * config syslog server level
         */
        $scope.downloadSyslog = function() {
            /**
             * lock screen
             */
            lockScreen.lock();

            var host = $scope.selectedAp.ip;
            //var url1 = "http://" + host + ":8080/downloadSyslog1";
            var url1 = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/downloadSyslog1";
            //var url2 = "http://" + host + ":8080/downloadSyslog2";
            var url2 = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/downloadSyslog2";
            var url3 = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/downloadSyslog3";
            //var url3 = "http://" + host + ":8080/downloadSyslog3";
            var filename1 = "kes_syslog";
            var filename2 = "kes_history_syslog.log";
            var filename3 = "kes_history_traps.log";

            var operatorMsg = "syslog_down";
            var logtemp = $scope.selectedAp.apname;
            var loginfo = [{
                'ip':host,
                'success':"module_operate_failure",
                'msg':''}];

            $http({
                method: 'put',
                url: url1,
                headers: {
                    'Authorization': 'sessionName ' + window.localStorage.sessionId
                }
            }).success(function(data, status, headers) {
                /**
                  * unlock screen
                  */
                lockScreen.unlock();

                if(data == null || data == ''){
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = "log_backendServer_error";
                }else{
                    if(typeof(data.success) == "undefined"){
                        saveFile(data, headers, filename1);
                        loginfo[0].success = "module_operate_success";
                        toastr.info($translate.instant("syslog_down_success_1"), '');
                    }else{
                        loginfo[0].success = "module_operate_failure";
                        toastr.info($translate.instant(data.msg), '');
                    }
                    loginfo[0].msg = data.msg;
                }

                operationLog.setLog(operatorMsg, loginfo, logtemp);
            }).error(function() {
                /**
                 * unlock screen
                 */
                lockScreen.unlock();

                loginfo[0].success = "module_operate_failure";
                loginfo[0].msg = "log_backendServer_error";
                operationLog.setLog(operatorMsg, loginfo, logtemp);

                toastr.warning($translate.instant("log_backendServer_error"), '');
            });

            $http({
                method: 'put',
                url: url2,
                headers: {
                    'Authorization': 'sessionName ' + window.localStorage.sessionId
                }
            }).success(function(data, status, headers) {
                /**
                 * unlock screen
                 */
                lockScreen.unlock();

                if(data == null || data == ''){
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = "log_backendServer_error";
                }else{
                    if(typeof(data.success) == "undefined"){
                        saveFile(data, headers, filename2);
                        loginfo[0].success = "module_operate_success";
                        toastr.info($translate.instant("syslog_down_success_2"), '');
                    }else{
                        loginfo[0].success = "module_operate_failure";
                        toastr.info($translate.instant(data.msg), '');
                    }
                    loginfo[0].msg = data.msg;
                }

                operationLog.setLog(operatorMsg, loginfo, logtemp);
            }).error(function() {
                /**
                 * unlock screen
                 */
                lockScreen.unlock();

                loginfo[0].success = "module_operate_failure";
                loginfo[0].msg = "log_backendServer_error";
                operationLog.setLog(operatorMsg, loginfo, logtemp);

                toastr.warning($translate.instant("log_backendServer_error"), '');
            });

            $http({
                method: 'put',
                url: url3,
                headers: {
                    'Authorization': 'sessionName ' + window.localStorage.sessionId
                }
            }).success(function(data, status, headers) {
                /**
                 * unlock screen
                 */
                lockScreen.unlock();

                if(data == null || data == ''){
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = "log_backendServer_error";
                }else{
                    if(typeof(data.success) == "undefined"){
                        saveFile(data, headers, filename3);
                        loginfo[0].success = "module_operate_success";
                        toastr.info($translate.instant("syslog_down_success_3"), '');
                    }else{
                        loginfo[0].success = "module_operate_failure";
                        toastr.info($translate.instant(data.msg), '');
                    }
                    loginfo[0].msg = data.msg;
                }

                operationLog.setLog(operatorMsg, loginfo, logtemp);
            }).error(function() {
                /**
                 * unlock screen
                 */
                lockScreen.unlock();

                loginfo[0].success = "module_operate_failure";
                loginfo[0].msg = "log_backendServer_error";
                operationLog.setLog(operatorMsg, loginfo, logtemp);

                toastr.warning($translate.instant("log_backendServer_error"), '');
            });
        };
}]);


