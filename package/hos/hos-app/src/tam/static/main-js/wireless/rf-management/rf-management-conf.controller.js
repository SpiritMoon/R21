angular.module('module.wireless.rfManagement')
    .filter("channelPowerFilter", [function() {
        var filterfun = function(value) {
            if(null === value){
                return "waiting";
            }else{
                return value;
            }
        };
        return filterfun;
    }])
    .controller('RfManagementConfController', ['$scope', '$modalInstance', 'authentifiedRequest', 'InterService', 'lockScreen', 'operationLog', 'toastr', '$translate', '$timeout', function($scope, $modalInstance, authentifiedRequest, InterService, lockScreen, operationLog, toastr, $translate, $timeout) {
        $scope.countryCodeInfo = {
            "countryCode":''
        };
        $scope.countryCodeInfo.countryCode = InterService.getCountryCodeInfo();


        $scope.skin = InterService.skin;
	    $scope.InterService = InterService;

        /**
         * RfManagement parameter init
         */
        $scope.apListParams = {};

        /**
         * supported 2g channels by country
         */
        $scope.Channel0_US = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        $scope.Channel0_JP = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        $scope.Channel0_DE = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        $scope.Channel0_CS = [];

        /**
         * supported 5g channels by country
         */
        $scope.Channel1_US = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 149, 153, 157, 161];
        $scope.Channel1_CA = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];
        $scope.Channel1_JP = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140];
        $scope.Channel1_KR = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161];
        $scope.Channel1_CN = [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165];
        $scope.Channel1_TW = [56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];
        $scope.Channel1_IL = [36, 40, 44, 48, 52, 56, 60, 64];
        $scope.Channel1_BO = [52, 56, 60, 64, 140, 149, 153, 157, 161, 165];
        $scope.Channel1_ID = [149, 153, 157, 161];
        $scope.Channel1_PK = [149, 153, 157, 161, 165];
        $scope.Channel1_DZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132];
        $scope.Channell_MY = [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165];
        $scope.Channel1_NG = [52, 56, 60, 64, 149, 153, 157, 161, 165];
        $scope.Channel1_PA = [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165];
        $scope.Channel1_RU = [36, 40, 44, 48, 52, 56, 60, 64, 132, 136, 140, 149, 153, 157, 161, 165];




        $scope.ChannelScope0 = [];
        $scope.select2gChannelScope = function(country){
            switch (country){
                case "JP":
                    $scope.ChannelScope0 = $scope.Channel0_JP;
                    break;
                case "DE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "NL":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "IT":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "PT":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "LU":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "NO":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "FI":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "DK":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "CH":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "CZ":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "ES":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "GB":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "KR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "CN":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "FR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "HK":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "SG":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "BR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "IL":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "SA":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "LB":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "AE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "ZA":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "AR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "AU":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "AT":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "BO":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "CL":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "GR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "IS":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "IN":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "KW":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "LI":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "LT":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MX":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MA":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "NZ":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "PL":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "SK":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "EE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MU":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "RO":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "ID":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "PE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "VE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "JM":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "BH":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "OM":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "JO":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "CO":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "GT":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "PH":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "LK":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "SV":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "TN":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "PK":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "QA":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "CS":
                    $scope.ChannelScope0 = $scope.Channel0_CS;
                    break;
                case "DZ":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "PA":
                    $scope.ChannelScope0 = $scope.Channel0_US;
                    break;
                case "BE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "EG":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "GB":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "GU":
                    $scope.ChannelScope0 = $scope.Channel0_US;
                    break;
                case "HU":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "IE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MC":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MK":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MT":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "MY":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "NG":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;

                case "RU":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "SE":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "TH":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "TR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "VN":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "HR":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                case "LV":
                    $scope.ChannelScope0 = $scope.Channel0_DE;
                    break;
                default :
                    $scope.ChannelScope0 = $scope.Channel0_US;
                    break;
            }
        };

        $scope.ChannelScope1 = [];
        $scope.select5gChannelScope = function(country){
            switch (country){
                case "BE":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "EG":
                    $scope.ChannelScope1 = $scope.Channel1_IL;
                    break;
                case "GB":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "GU":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "HU":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "IE":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "MC":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "MK":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "MT":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "MY":
                    $scope.ChannelScope1 = $scope.Channell_MY;
                    break;
                case "NG":
                    $scope.ChannelScope1 = $scope.Channel1_NG;
                    break;
                case "PA":
                    $scope.ChannelScope1 = $scope.Channel1_PA;
                    break;
                case "RU":
                    $scope.ChannelScope1 = $scope.Channel1_RU;
                    break;
                case "SE":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "TH":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "TR":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "VN":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "CA":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "HK":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "SG":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "BR":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "LB":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "AE":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "ZA":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "AR":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "AU":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "MX":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "NZ":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "PR":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "MU":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "CS":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "PE":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "JM":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "BM":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "CO":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "PH":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "LK":
                    $scope.ChannelScope1 = $scope.Channel1_CA;
                    break;
                case "JP":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "DE":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "NL":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "IT":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "PT":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "LU":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "NO":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "FI":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "DK":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "CH":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "CZ":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "ES":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "GB":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "FR":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "SA":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "AT":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "GR":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "IS":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "LI":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "LT":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "PL":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "SK":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "EE":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "RO":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "OM":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "GT":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "KR":
                    $scope.ChannelScope1 = $scope.Channel1_KR;
                    break;
                case "CN":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "CL":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "IN":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "VE":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "BH":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "DO":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "SV":
                    $scope.ChannelScope1 = $scope.Channel1_CN;
                    break;
                case "TW":
                    $scope.ChannelScope1 = $scope.Channel1_TW;
                    break;
                case "IL":
                    $scope.ChannelScope1 = $scope.Channel1_IL;
                    break;
                case "KW":
                    $scope.ChannelScope1 = $scope.Channel1_IL;
                    break;
                case "MA":
                    $scope.ChannelScope1 = $scope.Channel1_IL;
                    break;
                case "TN":
                    $scope.ChannelScope1 = $scope.Channel1_IL;
                    break;
                case "BO":
                    $scope.ChannelScope1 = $scope.Channel1_BO;
                    break;
                case "ID":
                    $scope.ChannelScope1 = $scope.Channel1_ID;
                    break;
                case "PK":
                    $scope.ChannelScope1 = $scope.Channel1_PK;
                    break;
                case "QA":
                    $scope.ChannelScope1 = $scope.Channel1_PK;
                    break;
                case "DZ":
                    $scope.ChannelScope1 = $scope.Channel1_DZ;
                    break;

                case "HR":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;
                case "LV":
                    $scope.ChannelScope1 = $scope.Channel1_JP;
                    break;

                default :
                    $scope.ChannelScope1 = $scope.Channel1_US;
                    break;
            }
        };

        $scope.initDivShow = function(){
            $scope.rfDetail = false;
            $scope.rfEdit = false;
        };
        $scope.initDivShow();

        function parseURL(url) {
            var a =  document.createElement('a');
            a.href = url;
            return {
                source: url,
                protocol: a.protocol.replace(':',''),
                host: a.hostname,
                port: a.port,
                query: a.search,
                params: (function(){
                    var ret = {},
                        seg = a.search.replace(/^\?/,'').split('&'),
                        len = seg.length, i = 0, s;
                    for (;i<len;i++) {
                        if (!seg[i]) { continue; }
                        s = seg[i].split('=');
                        ret[s[0]] = s[1];
                    }
                    return ret;
                })(),
                file: (a.pathname.match(/\/([^\/?#]+)$/i) || [,''])[1],
                hash: a.hash.replace('#',''),
                path: a.pathname.replace(/^([^\/])/,'/$1'),
                relative: (a.href.match(/tps?:\/\/[^\/]+(.+)/) || [,''])[1],
                segments: a.pathname.replace(/^\//,'').split('/')
            }
        };

        function getApInfo(apList, host){
            for(var i=0; i<apList.length; i++){
                if(host == apList[i].ip){
                    return apList[i];
                }
            }
        };

        /**
         * http request to obtain the configuration of RF
         */
        $scope.apListParams=[];
        $scope.query = function(editMac){
            var params ={};
            var firstLoop = true;

            /**
             * get ap list
             */
            var apList = InterService.getCanConfigAps();

            for(var i=0; i<apList.length; i++){
                var host = apList[i].ip;
                var url = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/rf";
                //var url = "http://" + host + ":8080/rf";
                authentifiedRequest.get(url, params, function(response, status, config, headers){
                    if (status == 200 && null != response && response.success){
                        var responseHost = parseURL(headers.url).host;;
                        var apInfo = getApInfo(apList, responseHost);
                        response.result.host = apInfo.ip;
                        response.result.apInfo = apInfo.apname;
                        response.result.apName = apInfo.name;
                        response.result.mac = apInfo.mac;

                        $scope.apListParams.push(response.result);
                        if(firstLoop){
                            $scope.rfDetail = true;
                            if(("" != editMac) && (editMac == mac)){
                                $scope.currentAP = response.result;
                            }else if("" == editMac){
                                $scope.currentAP = $scope.apListParams[0];
                            }
                            firstLoop = false;
                        }
                    }
                }, function(){
                    //console.info('query rf error!');
                });
            }
        };

        /**
         * call initialization method
         */
        $scope.query("");

        /**
         * config RF
         */
        $scope.newCurrentAP = {};
        $scope.save = function() {
            /**
             * lock screen
             */
            lockScreen.lock();

            var host = $scope.currentAP.host;
            var url = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/rf";
            //var url = "http://" + host + ":8080/rf";
            var params ={};

            $scope.newCurrentAP.host = $scope.currentAP.host;
            $scope.newCurrentAP.apInfo = $scope.currentAP.apInfo;
            $scope.newCurrentAP.apName = $scope.currentAP.apName;
            $scope.newCurrentAP.mac = $scope.currentAP.mac;
            $scope.newCurrentAP.country = $scope.currentAP.country;

            if($scope.oldAP.acsSwitch_2g != $scope.currentAP.acsSwitch_2g){
                if("ON" == $scope.currentAP.acsSwitch_2g){
                    $scope.newCurrentAP.channel_2g = "auto";
                }else{
                    $scope.newCurrentAP.channel_2g = $scope.currentAP.channel_2g;
                }
            }else{
                if(($scope.oldAP.channel_2g != $scope.currentAP.channel_2g) && ("OFF" == $scope.currentAP.acsSwitch_2g)){
                    $scope.newCurrentAP.channel_2g = $scope.currentAP.channel_2g;
                }
            }

            if($scope.oldAP.acsSwitch_5g != $scope.currentAP.acsSwitch_5g){
                if("ON" == $scope.currentAP.acsSwitch_5g){
                    $scope.newCurrentAP.channel_5g = "auto";
                }else{
                    $scope.newCurrentAP.channel_5g = $scope.currentAP.channel_5g;
                }
            }else{
                if(($scope.oldAP.channel_5g != $scope.currentAP.channel_5g) && ("OFF" == $scope.currentAP.acsSwitch_5g)){
                    $scope.newCurrentAP.channel_5g = $scope.currentAP.channel_5g;
                }
            }

            if($scope.oldAP.apcSwitch_2g != $scope.currentAP.apcSwitch_2g){
                if("ON" == $scope.currentAP.apcSwitch_2g){
                    $scope.newCurrentAP.power_2g = "auto";
                }else{
                    $scope.newCurrentAP.power_2g = $scope.currentAP.power_2g;
                }
            }else{
                if(($scope.oldAP.power_2g != $scope.currentAP.power_2g) && ("OFF" == $scope.currentAP.apcSwitch_2g)){
                    $scope.newCurrentAP.power_2g = $scope.currentAP.power_2g;
                }
            }

            if($scope.oldAP.apcSwitch_5g != $scope.currentAP.apcSwitch_5g){
                if("ON" == $scope.currentAP.apcSwitch_5g){
                    $scope.newCurrentAP.power_5g = "auto";
                }else{
                    $scope.newCurrentAP.power_5g = $scope.currentAP.power_5g;
                }
            }else{
                if(($scope.oldAP.power_5g != $scope.currentAP.power_5g) && ("OFF" == $scope.currentAP.apcSwitch_5g)){
                    $scope.newCurrentAP.power_5g = $scope.currentAP.power_5g;
                }
            }
            var requestParas = JSON.stringify($scope.newCurrentAP);

            authentifiedRequest.put(url, params, requestParas, function(response){
                /**
                 * unlock screen
                 */
                lockScreen.unlock();

                $scope.initDivShow();
                $scope.rfDetail=true;
                $scope.apListParams=[];
                $timeout(
                    function() {
                        $scope.query($scope.currentAP.mac);
                    }, 2000
                );
                $scope.newCurrentAP = {};

                var operatorMsg = "rf_edit";
                var logtemp = $scope.currentAP.mac;
                var loginfo = [{
                    'ip':host,
                    'success':"module_operate_failure",
                    'msg':''}];
                if(response == null || response == ''){
                    loginfo[0].success = "module_operate_failure";
                    loginfo[0].msg = 'log_backendServer_error';
                    toastr.info($translate.instant("log_backendServer_error"));
                }else{
                    if(response.success){
                        loginfo[0].success = "module_operate_success";
                    }else{
                        loginfo[0].success = "module_operate_failure";
                    }
                    loginfo[0].msg = response.msg;
                    toastr.info($translate.instant(response.msg));
                }
                operationLog.setLog(operatorMsg, loginfo, logtemp);
            }, function(){
                //console.info('edit rf error!');
                /**
                 * unlock screen
                 */
                lockScreen.unlock();
            });
        };

        /**
         * close button
         */
        $scope.cancel = function() {
            $modalInstance.close();
        };

        /**
         * show RF detail div
         */
        $scope.showDetail = function(item){
            $scope.rfDetail = true;
            $scope.rfEdit = false;
            $scope.currentAP = item;
        };

        /**
         * show RF config div
         */
        $scope.oldAP = {};
        $scope.showEdit = function(item){
            $scope.rfDetail = false;
            $scope.rfEdit = true;
            $scope.currentAP = angular.copy(item);
            $scope.oldAP = angular.copy(item);
            $scope.select2gChannelScope(item.country);
            $scope.select5gChannelScope(item.country);
        };
    }]);