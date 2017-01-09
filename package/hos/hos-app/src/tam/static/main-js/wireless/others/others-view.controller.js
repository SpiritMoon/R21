angular.module('module.wireless.others',[])
    .controller('OthersViewController', ['$scope', '$modal', 'authentifiedRequest', 'batchSyncConfig', 'InterService', function($scope, $modal, authentifiedRequest, batchSyncConfig, InterService) {
	    $scope.InterService = InterService;

        /* Wireles */
        $scope.backgroupScanningParams = {
            "backgroupScanning" : false,
            "scanInterval" : 5,
            "foreignChannelDuration" : 20
        };

        $scope.bandSteeringParams = {
            "bandSteering" : false
        };

        $scope.awareParams = {
            "aware" : false
        };

        /*network IGMP Snooping and ARP Proxy Snooping */
        $scope.igmpSnoopingParams = {
            'snoopingSwitch':false,
            'mulitowuicastSwitch':false,
            'hostLifeAgeingTime':90
        };

        $scope.ARPProxySnooping = {
            "proxySwitch":false
        };

        /*  slider */
        $scope.sliderParams = {
            scanIntervalOptions: [5, 6, 7, 8, 9, 10],
            foreignChannelOptions: [20, 30, 40, 50, 60],
            agingTimeOptions: [60, 90, 120, 150, 180]
        };

        $scope.setBackgroupSlider = function(){
            var currentScanInterval = $scope.backgroupScanningParams.scanInterval-5;
            var currentForeignChannel = $scope.backgroupScanningParams.foreignChannelDuration/10-2;
            $("#scan-interval-slider").slider("value", currentScanInterval);
            $("#foreign-channel-slider").slider("value",currentForeignChannel);
            if($scope.backgroupScanningParams.backgroupScanning == true){
                $("#scan-interval-slider").slider("enable");
                $("#foreign-channel-slider").slider("enable");
            }else{
                $("#scan-interval-slider").slider("disable");
                $("#foreign-channel-slider").slider("disable");
            }
        };

        $scope.setIGMPAgingTimgSlider = function(){
            var currentAgingTime = $scope.igmpSnoopingParams.hostLifeAgeingTime/30-2;
            $("#aging-time-slider").slider("value", currentAgingTime);
            if($scope.igmpSnoopingParams.snoopingSwitch == true){
                $("#aging-time-slider").slider("enable");
            }else{
                $("#aging-time-slider").slider("disable");
            }
        };

       /**
         * http request to obtain the configuration of igmpSnooping
         */         
       $scope.igmpSnoopingQuery = function(){
            authentifiedRequest.get("/network/igmpSnooping/confParams", null, function(data){
                if(data !=null && data.success){
                    $scope.igmpSnoopingParams = data.result;
                    $scope.setIGMPAgingTimgSlider();
                }              
            }, function(){});

        };

        //get arp_proxy parameter
        $scope.ARPProxySnoopingQuery = function(){

            authentifiedRequest.get("/network/arpProxy/confParams", null, function(data){
                if(data !=null && data.success){
                    $scope.ARPProxySnooping = data.result;
                }               
            }, function(){
            });

        };

        /**
        * data init
        **/
        $scope.toggleManager.otherInit = function(){
            $scope.BackgroundScanningQuery();
            $scope.BandSteeringQuery();
            $scope.AwareWirelessQuery();
            $scope.igmpSnoopingQuery();
            $scope.ARPProxySnoopingQuery();
        };

        /**
         * http request to obtain the configuration of background scanning
         */
        $scope.BackgroundScanningQuery = function(){
            var params ={};

            authentifiedRequest.get("/backgroupScanning", params, function(response, status){
                if(status == 200 && null != response && response.success){
                    $scope.backgroupScanningParams = response.result;
                    $scope.setBackgroupSlider();
                }
            }, function(){
                //console.info('query backgroupScanningParams error!');
            });
        };

        /**
         * Config Backgroup Scanning
         */
        $scope.configBackgroupScanningSwtich = function(){
            var requestParas = JSON.stringify($scope.backgroupScanningParams);
            var operatorMsg;
            if($scope.backgroupScanningParams.backgroupScanning){
                operatorMsg = "other_wireless_edit_backgroupScanningSwitch_1";
            }else{
                operatorMsg = "other_wireless_edit_backgroupScanningSwitch_2";
            }

            batchSyncConfig.request("put", "/backgroupScanningSwitch", null, requestParas, function(){
                $scope.BackgroundScanningQuery();
            }, null, operatorMsg);
        };

        $scope.configScanInterval = function(){
            var requestParas = JSON.stringify($scope.backgroupScanningParams);
            var operatorMsg = "other_wireless_edit_scanInterval";
            var logtemp = $scope.backgroupScanningParams.scanInterval;

            batchSyncConfig.request("put", "/scanInterval", null, requestParas, function(){
                $scope.BackgroundScanningQuery();
            }, null, operatorMsg, null, logtemp);
        };

        /*backgroup scan interval time slider*/
        var currentScanInterval = $scope.backgroupScanningParams.scanInterval-5;
        $("#scan-interval-slider")
            .slider({min:0, max:$scope.sliderParams.scanIntervalOptions.length-1, value:currentScanInterval})
            .slider("pips", {
                rest: "label",
                labels: $scope.sliderParams.scanIntervalOptions
            })
            .on("slidestop", function(e, ui){
                $("#scanIntervalValue").text($scope.sliderParams.scanIntervalOptions[ui.value]);
                $scope.backgroupScanningParams.scanInterval = $scope.sliderParams.scanIntervalOptions[ui.value];
                $scope.configScanInterval();
            });

        $scope.configForeignChannelDuration = function(){
            var requestParas = JSON.stringify($scope.backgroupScanningParams);
            var operatorMsg = "other_wireless_edit_foreignChannelDuration";
            var logtemp = $scope.backgroupScanningParams.foreignChannelDuration;

            batchSyncConfig.request("put", "/foreignChannelDuration", null, requestParas, function(){
                $scope.BackgroundScanningQuery();
            }, null, operatorMsg, null, logtemp);
        };

        var currentForeignChannel = $scope.backgroupScanningParams.foreignChannelDuration/10-2;
        $("#foreign-channel-slider")
            .slider({min:0, max:$scope.sliderParams.foreignChannelOptions.length-1, value:currentForeignChannel})
            .slider("pips", {
                rest: "label",
                labels: $scope.sliderParams.foreignChannelOptions
            })
            .on("slidestop", function(e, ui){
                $("#foreignChannelValue").text($scope.sliderParams.foreignChannelOptions[ui.value]);
                $scope.backgroupScanningParams.foreignChannelDuration = $scope.sliderParams.foreignChannelOptions[ui.value];
                $scope.configForeignChannelDuration();
            });

        /**
         * http request to obtain the configuration of band steering
         */
        $scope.BandSteeringQuery = function(){
            var params ={};

            authentifiedRequest.get("/bandSteering", params, function(response, status){
                if(status == 200 && null != response && response.success){
                    $scope.bandSteeringParams = response.result;
                }
            }, function(){
                //console.info('query bandSteeringParams error!');
            });
        };

        /**
         * Config Band Steering
         */
        $scope.configBandSteering = function(){
            var requestParas = JSON.stringify($scope.bandSteeringParams);
            var operatorMsg;
            if($scope.bandSteeringParams.bandSteering){
                operatorMsg = "other_wireless_edit_bandSteering_1";
            }else{
                operatorMsg = "other_wireless_edit_bandSteering_2";
            }

            batchSyncConfig.request("put", "/bandSteering", null, requestParas, function(){
                $scope.BandSteeringQuery();
            }, null, operatorMsg);
        };

        /**
         * http request to obtain the configuration of aware wireless
         */
        $scope.AwareWirelessQuery = function(){
            var params ={};

            authentifiedRequest.get("/aware", params, function(response, status){
                if(status == 200 && null != response && response.success){
                    $scope.awareParams = response.result;
                }
            }, function(){
                //console.info('query awareParams error!');
            });
        };

        /**
         * Config Aware Wireless
         */
        $scope.configAware = function(){
            var requestParas = JSON.stringify($scope.awareParams);
            var operatorMsg;
            if($scope.awareParams.aware){
                operatorMsg = "other_wireless_edit_aware_1";
            }else{
                operatorMsg = "other_wireless_edit_aware_2";
            }

            batchSyncConfig.request("put", "/aware", null, requestParas, function(){
                $scope.AwareWirelessQuery();
            }, null, operatorMsg);
        };

        /**
         * Config Network IGMP Snooping and ARP Proxy Snooping
         */
        $scope.igmpSnoopingParamChange = function(option){
            var data = {'igmpOption':option,'igmpOptionValue':0};

            var operatorMsg ='';
            switch(option){
                case 'switch':
                    if($scope.igmpSnoopingParams.snoopingSwitch){
                        data.igmpOptionValue = 1;
                        operatorMsg = 'other_log_igmpSnoopingSwitch_open';
                    }else{
                        $scope.igmpSnoopingParams.mulitowuicastSwitch = false;
                        operatorMsg = 'other_log_igmpSnoopingSwitch_close';
                    }
                    break;
                case 'multounicast':
                    if($scope.igmpSnoopingParams.mulitowuicastSwitch){
                        data.igmpOptionValue = 1;
                        operatorMsg = 'other_log_MulticastToUnicastSwitch_open';
                    }else{
                        operatorMsg = 'other_log_MulticastToUnicastSwitch_close';
                    }
                    break;
                case 'hostlifeinterval':
                    data.igmpOptionValue = Number($scope.igmpSnoopingParams.hostLifeAgeingTime);
                    operatorMsg = 'other_log_igmpSnoopingAgingTime_config';
            }

            batchSyncConfig.request('put', '/network/igmpSnooping/confParams', null, data, function(){
                $scope.igmpSnoopingQuery();
            },null,operatorMsg);

        };
        var currentAgingTime = $scope.igmpSnoopingParams.hostLifeAgeingTime/30-2;
        $("#aging-time-slider")
            .slider({min:0, max:$scope.sliderParams.agingTimeOptions.length-1, value:currentAgingTime})
            .slider("pips", {
                rest: "label",
                labels: $scope.sliderParams.agingTimeOptions
            })
            .on("slidestop", function(e, ui){
                $("#age_value").text($scope.sliderParams.agingTimeOptions[ui.value]);
                $scope.igmpSnoopingParams.hostLifeAgeingTime = $scope.sliderParams.agingTimeOptions[ui.value];
                $scope.igmpSnoopingParamChange('hostlifeinterval');
            });

        /**
         * Config  ARPProxySnooping
         */
        $scope.ARPProxySnoopingChange= function(){
            var data = {'proxySwitch':0};
            var operatorMsg ='other_log_proxySwitch_close';
            if($scope.ARPProxySnooping.proxySwitch){
                data.proxySwitch = 1;
                operatorMsg ='other_log_proxySwitch_open';
            }
            
            batchSyncConfig.request('put', '/network/arpProxy/confParams', null, data, function(){
                 $scope.ARPProxySnoopingQuery();
            },null,operatorMsg);

        };
    }]);