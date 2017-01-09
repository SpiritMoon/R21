angular.module('wlan')
    .filter("enableFilter", [function() {
        var filterfun = function(value) {
            switch(value){
                case true:
                    return "Yes";
                    break;
                case false:
                    return "No";
                    break;
            }
        };
        return filterfun;
    }])
    .filter("wlanStatusFilter", ['$translate', function($translate){
        var filterfun = function(value) {
            switch(value){
                case true:
                    return  $translate.instant("Enable");
                    break;
                case false:
                    return  $translate.instant("Disable");
                    break;
            }
        };
        return filterfun;
    }])
    .controller("listContronller", ['$scope', '$modalInstance','$translate', 'InterService', 'authentifiedRequest', 'batchSyncConfig', 'toastr', 'wlans', 'hanCrypto', '$timeout', function($scope, $modalInstance,$translate, InterService, authentifiedRequest, batchSyncConfig, toastr, wlans, hanCrypto, $timeout) {
        //define skin
        $scope.skin = InterService.skin;

        //hidden security display when create WLAN
        $scope.isPersonal = false;
        $scope.isEnterprise = false;
        //the edit and create function control captive hide or show
        $scope.isCapital = false;
        //the detail control captive hide or show
        $scope.isCaptivePortal = false;

        //hidden security display when edit  WLAN
        $scope.isDetailPersonal = false;
        $scope.isDetailEnterprise = false;
        $scope.ST = {editSecurity:{id:"",name:"",units:[]}};
        $scope.Encryption = {editEncryption:{id:"",name:"",value:""}};
	    $scope.InterService = InterService;
        $scope.FORMAT = {formatSelected:{id:"",name:""}};
        //control select disabled
        $scope.disabledSelect = false;
        /**
         * WLAN parameter init
         */
        $scope.wlanList = wlans;


        //define wlan band
        $scope.band = {
            twoG: true,
            fiveG: true
        };


        //init
        $scope.isTwoG = true;
        $scope.countryCode =  InterService.getCountryCode();
        if($scope.countryCode == "CS"){
            $scope.band = {twoG: false,fiveG: true};
            $scope.isTwoG = false;
        }

        //select data
        $scope.securityTypeArray = [
            {id: "00",name: "Open",units: []},
            {id: "01", name: "Personal", units: [
                {id: "0109",name: "Both(wpa &wpa2)",value:"psk-mixed+tkip+aes"},
                {id: "0107",name: "wpa2-personal",value:"psk2+aes"}

            ]},
            {id: "02", name: "Enterprise", units: [
                {id: "0209",name: "Both(wpa &wpa2)",value:"wpa-mixed+tkip+aes"},
                {id: "0207",name: "wpa2-enterprise",value:"wpa2+aes"}
            ]}];


        $scope.passphraseFormatArray = [
            {
            id: "1",
            name: "8-63 chars"
        }, {
            id: "2",
            name: "64 Hexadecimal chars"
        }];
        $scope.createSecurity = $scope.securityTypeArray[1];
        $scope.createEncryption = $scope.createSecurity.units[0];
        $scope.selectedAT = $scope.securityTypeArray[0];
        $scope.formatSelected = $scope.passphraseFormatArray[0];



        //redis switch
        $scope.redisSwitch = {isSwitch:false};
        $scope.isRedisShow = false;
        $scope.redisChange = function (isTRUE) {
            if(isTRUE){
                $scope.isRedisShow = true;
                console.info("this is  "+ isTRUE);
            }else{
                $scope.isRedisShow = false;
                console.info("this is  "+ isTRUE);
            }
        }




        //div hide show
        $scope.initDivShow = function() {
            $scope.isCreate = false;
            $scope.isEdit = false;
            $scope.isDetail = false;
            $scope.isWmm = false;
            $scope.isWmmEdit = false;
        };
        $scope.initDivShow();

        //password check
        $scope.fprmatMsg = {flag:0,msg:""};
        $scope.selecFormat  = function () {
            if(this.formatSelected.id =="1"){
                $scope.fprmatMsg.flag = 1;
                $scope.fprmatMsg.msg = $translate.instant("enter8-63Chars");
            }else if(this.formatSelected.id =="2"){
                $scope.fprmatMsg.flag = 2;
                $scope.fprmatMsg.msg =$translate.instant("enter64Chars");
            }
        };

        //wmm data
        $scope.uplink = {
            dscpBg: '',
            dscpBe: '',
            dscpVideo: '',
            dscpVoice: '',
            eightBg: '',
            eightBe: '',
            eightVideo: '',
            eightVoice: ''
        };
        $scope.downlink = {
            dscpBg: "",
            dscpBe: "",
            dscpVideo: "",
            dscpVoice: "",
            eightBg: "",
            eightBe: "",
            eightVideo: "",
            eightVoice: ""
        };

        //wmm switch
        $scope.wmmd= {
            'dscpSwitch': false,
            'dot1pSwitch': false
        };

        $scope.urlEscape = function(url){
            url = url.replace(/\+/g, "%2B");
            url = url.replace(/\//g, "%2F");
            url = url.replace(/\?/g, "%3F");
            url = url.replace(/%/g, "%25");
            url = url.replace(/#/g, "%23");
            url = url.replace(/&/g, "%26");
            url = url.replace(/=/g, "%3D");
            url = url.replace(/\\/g, "%5C");
            url = url.replace(/\./g, "%2E");
            url = url.replace(/:/g, "%3A");

            return url;
        };

        /**
         * http request to obtain the configuration of wlan
         */
        $scope.query = function(ssid) {
            var params = {};

            authentifiedRequest.get("/wlans", params, function(response, status) {
                if (status == 200 && null != response && response.success){
                    //decoder key
                    for (var i = 0; i < response.result.wlanList.length; i++) {
                        response.result.wlanList[i].key = hanCrypto.decoder(response.result.wlanList[i].key);
                        response.result.wlanList[i].authSecret = hanCrypto.decoder(response.result.wlanList[i].authSecret);
                        response.result.wlanList[i].acctSecret = hanCrypto.decoder(response.result.wlanList[i].acctSecret);
                    }

                    $scope.wlanList = response.result.wlanList;
                    if ("" != ssid) {
                        for (var i = 0; i < $scope.wlanList.length; i++) {
                            if (ssid == $scope.wlanList[i].ssid) {
                                $scope.currentWlan = $scope.wlanList[i];
                                break;
                            }
                        }
                    }
                }
            }, function() {
                //console.info('query wlan list error!');
            });
        };

        /**
         * close button
         */
        $scope.cancel = function() {
            $modalInstance.close();
        };

        /**
         * show new wlan div
         */
        $scope.newWlan = { "authPort" : 1812, "acctPort" : 1813};

        $scope.showCreate = function() {
            $scope.newWlan.maxClients = 64;
            $scope.newWlan.probeThreshold = 0;
            $scope.newWlan.hidden = "No";
            $scope.newWlan.enable = "Yes";
            $scope.newWlan.captivePortal = "No";
            $scope.newWlan.vlanId = 0;
            $scope.newWlan.upstreamLimit = 0;
            $scope.newWlan.downstreamLimit = 0;
            $scope.isPersonal = true;
            $scope.isEnterprise = false;
            $scope.isDetailPersonal = false;
            $scope.isDetailEnterprise = false;
            $scope.isCreate = true;
            $scope.isEdit = false;
            $scope.isDetail = false;
            $scope.isWmm = false;
            $scope.isWmmEdit = false;
			$scope.isCapital = false;
            $scope.redisSwitch.isSwitch = true;
	        this.createSecurity = $scope.securityTypeArray[1];
            this.createEncryption = this.createSecurity.units[0];
        };


        //add wlan switch securityType
        $scope.changeSecurityType = function() {
            if (this.createSecurity.id == "00") {
                $scope.isPersonal = false;
                $scope.isEnterprise = false;
                $scope.isCapital = true;
            } else if (this.createSecurity.id == "01") {
                $scope.isPersonal = true;
                $scope.isEnterprise = false;
                $scope.isCapital = false;
                this.createEncryption = this.createSecurity.units[0];
            } else if (this.createSecurity.id == "02") {
                $scope.isPersonal = false;
                $scope.isEnterprise = true;
                $scope.isCapital = false;
                $scope.isRedisShow = false;
                $scope.redisSwitch.isSwitch = false;
                this.createEncryption = this.createSecurity.units[0];
            }
        };

        $scope.isWlanExist = function(wlanSsid, wlanList){
            for(var i=0; i<wlanList.length; i++) {
                if(wlanSsid == wlanList[i].ssid){
                    return true;
                }
            }
            return false;
        };

        /**
         * add wlan
         */
        $scope.createWlan = function() {
            if($scope.isWlanExist($scope.newWlan.ssid, $scope.wlanList)){
                toastr.info($translate.instant("wlanAlreadyExist1")+$scope.newWlan.ssid+$translate.instant("wlanAlreadyExist2"), '');
            }else{
                if (($scope.band.twoG) && ($scope.band.fiveG)) {
                    $scope.newWlan.band = "2G,5G";
                } else if ($scope.band.twoG) {
                    $scope.newWlan.band = "2G";
                } else if($scope.band.fiveG){
                    $scope.newWlan.band = "5G";
                } else {
                toastr.info($translate.instant("pleaseSelectedBand"), '');
                    return;
                }

                $scope.newWlan.securityType = this.createSecurity.name;
                if($scope.securityTypeArray[0].name !== $scope.newWlan.securityType){
                    $scope.newWlan.encryption = this.createEncryption.value;
                }
                if(!$scope.redisSwitch.isSwitch){
                    $scope.newWlan.acctServer = "";
                    $scope.newWlan.acctPort = "";
                    $scope.newWlan.acctSecret = "";
                }

                //encoder key
                var encoderNewWlan = angular.copy($scope.newWlan);
                encoderNewWlan.key = hanCrypto.encoder(encoderNewWlan.key);
                encoderNewWlan.keyConfirm = hanCrypto.encoder(encoderNewWlan.keyConfirm);
                encoderNewWlan.authSecret = hanCrypto.encoder(encoderNewWlan.authSecret);
                encoderNewWlan.acctSecret = hanCrypto.encoder(encoderNewWlan.acctSecret);

                var requestParas = JSON.stringify(encoderNewWlan);
                var operatorMsg = "wlan_add_1";
                var logtemp = $scope.newWlan.ssid;

                batchSyncConfig.request("post", "/advanceWlan", null, requestParas, function() {
                    $scope.newWlan = {};
                    $scope.band.twoG = true;
                    $scope.band.fiveG = true;
                    $scope.initDivShow();
                    $scope.isDetail = true;
                    $timeout(
                        function() {
                            $scope.query(encoderNewWlan.ssid);
                        }, 2000
                    );
                }, null, operatorMsg, null, logtemp);
            }
        };

        /**
         * show edit wlan div
         */
        $scope.oldssid = "";
        $scope.oldWlan = {};
        $scope.showEdit = function(item) {
            $scope.oldssid = item.ssid;
            //$scope.securityTypeArray = $scope.securityTypeArray_1;
            //echo securityType
            if(item.securityType == "open"){
                this.ST.editSecurity = $scope.securityTypeArray[0];
                $scope.isDetailPersonal = false;
                $scope.isDetailEnterprise = false;
                $scope.isCapital = true;
            }else if(item.securityType == "personal"){
                $scope.isCapital = false;
                this.ST.editSecurity = $scope.securityTypeArray[1];
                $scope.isDetailPersonal = true;
                $scope.isDetailEnterprise = false;
				item.keyConfirm = item.key;

                if(item.encryption == "psk-mixed+tkip+aes"){
                    this.Encryption.editEncryption = this.ST.editSecurity.units[0];
                }else if(item.encryption == "psk2+aes"){
                    this.Encryption.editEncryption = this.ST.editSecurity.units[1];
                }
            }else if(item.securityType == "enterprise"){
                $scope.isCapital = false;
                $scope.isDetailPersonal = false;
                $scope.isDetailEnterprise = true;
                this.ST.editSecurity = $scope.securityTypeArray[2];

                if(item.encryption == "wpa-mixed+tkip+aes"){
                    this.Encryption.editEncryption = this.ST.editSecurity.units[0];
                }else if(item.encryption == "wpa2+aes"){
                    this.Encryption.editEncryption = this.ST.editSecurity.units[1];
                }
                if(item.acctServer != null && item.acctServer != ""){
                    $scope.redisSwitch.isSwitch = true;
                    $scope.isRedisShow = true;

                }else{
                    $scope.redisSwitch.isSwitch = false;
                    $scope.isRedisShow = false;
                }

            }


            console.info(item.key);
            if(item.key.length == 64){
                this.FORMAT.formatSelected = $scope.passphraseFormatArray[1];
            }else{
				this.FORMAT.formatSelected = $scope.passphraseFormatArray[0];
			}
            console.info(this.FORMAT.formatSelected);

            $scope.currentWlan = angular.copy(item);
            $scope.oldWlan = angular.copy(item);
            $scope.isCreate = false;
            $scope.isEdit = true;
            $scope.isDetail = false;
            $scope.isWmm = false;
            $scope.isWmmEdit = false;
        };

        //edit wlan switch securityType
        $scope.changeSecurity = function() {
            $scope.ST.editSecurity = this.ST.editSecurity;
            if (this.ST.editSecurity.id == "00") {
                $scope.isDetailPersonal = false;
                $scope.isDetailEnterprise = false;
				$scope.isCapital = true;
                $scope.currentWlan.authPort = "";
                $scope.currentWlan.acctPort = "";
            } else if (this.ST.editSecurity.id == "01") {
                $scope.isDetailPersonal = true;
                $scope.isDetailEnterprise = false;
				$scope.isCapital = false;
                this.Encryption.editEncryption = this.ST.editSecurity.units[0];
                $scope.currentWlan.authPort = "";
                $scope.currentWlan.acctPort = "";
            } else if (this.ST.editSecurity.id == "02") {
                $scope.isDetailPersonal = false;
                $scope.isDetailEnterprise = true;
				$scope.isCapital = false;
                $scope.isRedisShow = false;
                $scope.redisSwitch.isSwitch = false;
                this.Encryption.editEncryption = this.ST.editSecurity.units[0];
                $scope.currentWlan.authPort = 1812;
                $scope.currentWlan.acctPort = 1813;
            }
        };

        /**
         * edit wlan
         */
        $scope.newCurrentWlan = {};
        $scope.editWlan = function() {
			if($scope.oldWlan.ssid != $scope.currentWlan.ssid){
				if($scope.isWlanExist($scope.currentWlan.ssid, $scope.wlanList)){
					toastr.info($translate.instant("wlanAlreadyExist1")+$scope.currentWlan.ssid+$translate.instant("wlanAlreadyExist2"), '');
					return;
				}
			}
            
           
            if (($scope.band.twoG) && ($scope.band.fiveG)) {
                $scope.currentWlan.band = "2G,5G";
            } else if ($scope.band.twoG) {
                $scope.currentWlan.band = "2G";
            } else {
                $scope.currentWlan.band = "5G";
            }
            $scope.currentWlan.securityType = this.ST.editSecurity.name;
            if($scope.securityTypeArray[0].name !== $scope.currentWlan.securityType){
                $scope.currentWlan.encryption = this.Encryption.editEncryption.value;
            }

            if($scope.oldWlan.ssid != $scope.currentWlan.ssid){
                $scope.newCurrentWlan.ssid = $scope.currentWlan.ssid;
            }
            if($scope.oldWlan.enable != $scope.currentWlan.enable){
                $scope.newCurrentWlan.enable = $scope.currentWlan.enable;
            }
            if($scope.oldWlan.hidden != $scope.currentWlan.hidden){
                $scope.newCurrentWlan.hidden = $scope.currentWlan.hidden;
            }
            if($scope.oldWlan.maxClients != $scope.currentWlan.maxClients){
                $scope.newCurrentWlan.maxClients = $scope.currentWlan.maxClients;
            }
            if($scope.oldWlan.probeThreshold != $scope.currentWlan.probeThreshold){
                $scope.newCurrentWlan.probeThreshold = $scope.currentWlan.probeThreshold;
            }
            if($scope.oldWlan.vlanId != $scope.currentWlan.vlanId){
                $scope.newCurrentWlan.vlanId = $scope.currentWlan.vlanId;
            }
            if($scope.oldWlan.upstreamLimit != $scope.currentWlan.upstreamLimit){
                $scope.newCurrentWlan.upstreamLimit = $scope.currentWlan.upstreamLimit;
            }
            if($scope.oldWlan.downstreamLimit != $scope.currentWlan.downstreamLimit){
                $scope.newCurrentWlan.downstreamLimit = $scope.currentWlan.downstreamLimit;
            }
            if($scope.oldWlan.securityType.toUpperCase()  != $scope.currentWlan.securityType.toUpperCase()){
                $scope.newCurrentWlan.securityType = $scope.currentWlan.securityType;
            }
            if($scope.oldWlan.encryption != $scope.currentWlan.encryption){
                $scope.newCurrentWlan.encryption = $scope.currentWlan.encryption;
            }

            if($scope.currentWlan.securityType == "Open"){
                $scope.newCurrentWlan.key = "";
                $scope.newCurrentWlan.authServer = "";
                $scope.newCurrentWlan.authPort = "";
                $scope.newCurrentWlan.authSecret = "";
                $scope.newCurrentWlan.acctServer = "";
                $scope.newCurrentWlan.acctPort = "";
                $scope.newCurrentWlan.acctSecret = "";

                if($scope.oldWlan.captivePortal != $scope.currentWlan.captivePortal){
                    $scope.newCurrentWlan.captivePortal = $scope.currentWlan.captivePortal;
                }
				
				if($scope.oldWlan.fast){
                    $scope.newCurrentWlan.fast = 0;
                }

                if($scope.oldWlan.okc){
                    $scope.newCurrentWlan.okc = 0;
                }
            }else if($scope.currentWlan.securityType == "Personal"){
                if($scope.oldWlan.key != $scope.currentWlan.key){
                    //encoder key
                    $scope.newCurrentWlan.key = hanCrypto.encoder($scope.currentWlan.key);
                }
                if($scope.oldWlan.fast != $scope.currentWlan.fast){
                    $scope.newCurrentWlan.fast = $scope.currentWlan.fast;
                }
                if($scope.oldWlan.captivePortal == "Yes"){
                    $scope.newCurrentWlan.captivePortal = "No";
                }

                $scope.newCurrentWlan.authServer = "";
                $scope.newCurrentWlan.authPort = "";
                $scope.newCurrentWlan.authSecret = "";
                $scope.newCurrentWlan.acctServer = "";
                $scope.newCurrentWlan.acctPort = "";
                $scope.newCurrentWlan.acctSecret = "";
                //encoder keyConfirm
                $scope.newCurrentWlan.keyConfirm = hanCrypto.encoder($scope.currentWlan.keyConfirm);
            }else if($scope.currentWlan.securityType == "Enterprise"){
                $scope.newCurrentWlan.key = "";
                if($scope.oldWlan.authServer != $scope.currentWlan.authServer){
                    $scope.newCurrentWlan.authServer = $scope.currentWlan.authServer;
                }
                if($scope.oldWlan.authPort == ""){//this security type is open,and the authPort use default value 1812
                    $scope.newCurrentWlan.authPort = 1812;
                }
                if($scope.oldWlan.authPort != $scope.currentWlan.authPort){//
                    $scope.newCurrentWlan.authPort = $scope.currentWlan.authPort;
                }
                if($scope.oldWlan.authSecret != $scope.currentWlan.authSecret){
                    //encoder authSecret
                    $scope.newCurrentWlan.authSecret = hanCrypto.encoder($scope.currentWlan.authSecret)
                }
                if($scope.oldWlan.acctServer != $scope.currentWlan.acctServer){
                    $scope.newCurrentWlan.acctServer = $scope.currentWlan.acctServer;
                }
                //if($scope.oldWlan.acctPort == ""){//this security type is open,and the acctPort use default value 1813
                //    $scope.newCurrentWlan.acctPort = 1813;
                //}
                //if($scope.oldWlan.acctPort != $scope.currentWlan.acctPort){
                //    $scope.newCurrentWlan.acctPort = $scope.currentWlan.acctPort;
                //}
                if($scope.oldWlan.acctSecret != $scope.currentWlan.acctSecret){
                    //encoder acctSecret
                    $scope.newCurrentWlan.acctSecret =hanCrypto.encoder($scope.currentWlan.acctSecret) ;
                }
                if($scope.oldWlan.captivePortal == "Yes"){
                    $scope.newCurrentWlan.captivePortal = "No";
                }

                if($scope.oldWlan.fast != $scope.currentWlan.fast){
                    if($scope.currentWlan.fast){
                        $scope.newCurrentWlan.fast = 1;
                    }else{
                        $scope.newCurrentWlan.fast = 0;
                    }
                }
                if($scope.oldWlan.okc != $scope.currentWlan.okc){
                    if($scope.currentWlan.okc){
                        $scope.newCurrentWlan.okc = 1;
                    }else{
                        $scope.newCurrentWlan.okc = 0;
                    }
                }

                if(!$scope.redisSwitch.isSwitch){
                    $scope.newCurrentWlan.acctServer = "";
                    $scope.newCurrentWlan.acctPort = "";
                    $scope.newCurrentWlan.acctSecret = "";
                }else{
                    $scope.newCurrentWlan.acctPort = $scope.currentWlan.acctPort;
                }
            }

            var requestParas = JSON.stringify($scope.newCurrentWlan);
            var operatorMsg = "wlan_edit";
            var logtemp = $scope.oldssid;

            batchSyncConfig.request("put", "/wlan/" + $scope.urlEscape($scope.oldssid), null, requestParas, function() {
                $scope.initDivShow();
                $scope.isDetail = true;
                $timeout(
                    function() {
                        $scope.query($scope.newCurrentWlan.ssid);
                        $scope.newCurrentWlan = {};
                    }, 2000
                );
            }, null, operatorMsg, null, logtemp);
        };

        /**
         * show wlan detail div
         */
        $scope.viewWlan = {};
        $scope.username = window.localStorage.username;
        $scope.isDetailRedius = false;
        $scope.showDetail = function(item) {
            $scope.viewWlan = angular.copy(item);
            if ($scope.viewWlan.securityType == "open") {
                $scope.isPersonInfo = false;
                $scope.isEnterpriseInfo = false;
                $scope.isCaptivePortal = true;
            } else if ($scope.viewWlan.securityType == "personal") {
                $scope.viewWlan.key = "**************";
                if(item.encryption == "psk-mixed+tkip+aes"){
                    $scope.viewWlan.encryption = $scope.securityTypeArray[1].units[0].name;
                }else if(item.encryption == "psk2+aes"){
                    $scope.viewWlan.encryption = $scope.securityTypeArray[1].units[1].name;
                }
                $scope.isPersonInfo = true;
                $scope.isEnterpriseInfo = false;
                $scope.isCaptivePortal = false;
            } else if ($scope.viewWlan.securityType == "enterprise") {
                $scope.viewWlan.authSecret = "**************";
                if( $scope.viewWlan.acctServer==null || $scope.viewWlan.acctServer==""){
                    $scope.isDetailRedius = false;
                }else {
                    $scope.isDetailRedius = true;
                    $scope.viewWlan.acctSecret = "**************";
                }
                if(item.encryption == "wpa-mixed+tkip+aes"){
                    $scope.viewWlan.encryption = $scope.securityTypeArray[2].units[0].name;
                }else if(item.encryption == "wpa2+aes"){
                    $scope.viewWlan.encryption = $scope.securityTypeArray[2].units[1].name;
                }

                $scope.isPersonInfo = false;
                $scope.isEnterpriseInfo = true;
                $scope.isCaptivePortal = false;
            }
            if ($scope.viewWlan.fast) {
                $scope.viewWlan.fast = "Open";
            }else {
                $scope.viewWlan.fast = "Close";
            }

            if($scope.viewWlan.okc){
                $scope.viewWlan.okc = "Open";
            }else{
                $scope.viewWlan.okc = "Close";
            }

            $scope.isCreate = false;
            $scope.isEdit = false;
            $scope.isDetail = true;
            $scope.isWmm = false;
            $scope.isWmmEdit = false;
        };

        /**
         * delete wlan
         */
        $scope.deleteWlan = function(ssid) {
            var operatorMsg = "wlan_delete";
            var logtemp = ssid;
            var confirm_tip =$translate.instant("delWlan") + ssid + " ?";
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
                    if(result) {
                        batchSyncConfig.request("delete", "/wlan/" + $scope.urlEscape(ssid), null, null, function() {
                            $timeout(
                                function() {
                                    $scope.query("");
                                }, 2000
                            );
                        }, null, operatorMsg, null, logtemp);
                    }
                }
            });

            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        batchSyncConfig.request("delete", "/wlan/" + $scope.urlEscape(ssid), null, null, function() {
            //            $timeout(
            //                function() {
            //                    $scope.query("");
            //                }, 2000
            //            );
            //        }, null, operatorMsg, null, logtemp);
            //    }
            //}
            //);
        };

        /**
         * query wlan wmm parameter
         */
        $scope.queryWmmParam = function(ssid) {

            authentifiedRequest.get("/wlan/" + ssid + "/wmm/confParams", null, function(response) {
                if (response != null && response.success) {
                    //assignment
                    var obj = response.result;
                    $scope.uplink.dscpBg = obj.bk_to_dscp;
                    $scope.uplink.dscpBe = obj.be_to_dscp;
                    $scope.uplink.dscpVideo = obj.vi_to_dscp;
                    $scope.uplink.dscpVoice = obj.vo_to_dscp;
                    $scope.uplink.eightBg = obj.bk_to_dot1p;
                    $scope.uplink.eightBe = obj.be_to_dot1p;
                    $scope.uplink.eightVideo = obj.vi_to_dot1p;
                    $scope.uplink.eightVoice = obj.vo_to_dot1p;

                    $scope.downlink.dscpBg = obj.dscp_to_bk;
                    $scope.downlink.dscpBe = obj.dscp_to_be;
                    $scope.downlink.dscpVideo = obj.dscp_to_vi;
                    $scope.downlink.dscpVoice = obj.dscp_to_vo;
                    $scope.downlink.eightBg = obj.dot1p_to_bk;
                    $scope.downlink.eightBe = obj.dot1p_to_be;
                    $scope.downlink.eightVideo = obj.dot1p_to_vi;
                    $scope.downlink.eightVoice = obj.dot1p_to_vo;
                    $scope.wmmd.dscpSwitch = obj.dscp_enable;
                    $scope.wmmd.dot1pSwitch = obj.dot1p_enable;

                } 
            }, function() { //error

            });
        };

        /**
         * show wmm div
         */
        $scope.showWmm = function(ssid) {
            //data clear
            $scope.uplink = {
                dscpBg: '',
                dscpBe: '',
                dscpVideo: '',
                dscpVoice: '',
                eightBg: '',
                eightBe: '',
                eightVideo: '',
                eightVoice: ''
            };
            $scope.downlink = {
                dscpBg: "",
                dscpBe: "",
                dscpVideo: "",
                dscpVoice: "",
                eightBg: "",
                eightBe: "",
                eightVideo: "",
                eightVoice: ""
            };


            $scope.wmmd.dscpSwitch = false;
            $scope.wmmd.dot1pSwitch = false;

            $scope.wmmSsid = $scope.urlEscape(ssid); //use when save

            //display control
            $scope.isCreate = false;
            $scope.isEdit = false;
            $scope.isDetail = false;
            $scope.isWmm = true;
            $scope.isWmmEdit = false;

            //view data loading
            $scope.queryWmmParam($scope.wmmSsid);
        };

        /**
         * show edit wmm div
         */
        $scope.showEditWmm = function() {
            $scope.isWmm = false;
            $scope.isWmmEdit = true;
        };

		/**
		* cancel wmm and show detail
		*/
		
		$scope.cancelWmm = function () {
            $scope.queryWmmParam($scope.wmmSsid);
            $scope.isWmm = true;
            $scope.isWmmEdit = false;
        }
		
        /**
         * wmm switch change
         */
        $scope.wmmswitchchange = function(switchType) {
            var ssid = $scope.wmmSsid;
            var data = {
                'switchType':switchType,
                'switchValue': 0
            };
            var operatorMsg = 'wmm_log_close';
            if('dscp_enable' == switchType && $scope.wmmd.dscpSwitch){
                data.switchValue  = 1;
                operatorMsg = 'wmm_log_open';
            }else if('dot1p_enable' == switchType && $scope.wmmd.dot1pSwitch){
                data.switchValue  = 1;
                operatorMsg = 'wmm_log_open';
            }   

            if('dscp_enable' == switchType ){
                 operatorMsg = operatorMsg + '_dscpswitch';
            } else{
                 operatorMsg = operatorMsg + '_dot1pwitch';
            }     

            batchSyncConfig.request("put", "/wlan/" + ssid + "/wmmSwitch", null, data, function() {
                $scope.isWmmEdit = false;
                $scope.isWmm = true;
                $scope.queryWmmParam(ssid);
            },null,operatorMsg);
        };

        /**
         * save WMM parameter
         */
        $scope.validFlag = false;
        $scope.saveWmmInfo = function() {
            var ssid = $scope.wmmSsid;

            //WMM parameter assignment
            var data = {
                'bk_to_dscp': "",
                'be_to_dscp': "",
                'vi_to_dscp': "",
                'vo_to_dscp': "",
                'bk_to_dot1p': "",
                'be_to_dot1p': "",
                'vi_to_dot1p': "",
                'vo_to_dot1p': "",
                'dscp_to_bk': "",
                'dscp_to_be': "",
                'dscp_to_vi': "",
                'dscp_to_vo': "",
                'dot1p_to_bk': "",
                'dot1p_to_be': "",
                'dot1p_to_vi': "",
                'dot1p_to_vo': ""
            };

            data.bk_to_dscp = $scope.uplink.dscpBg;
            data.be_to_dscp = $scope.uplink.dscpBe;
            data.vi_to_dscp = $scope.uplink.dscpVideo;
            data.vo_to_dscp = $scope.uplink.dscpVoice;
            data.bk_to_dot1p = $scope.uplink.eightBg;
            data.be_to_dot1p = $scope.uplink.eightBe;
            data.vi_to_dot1p = $scope.uplink.eightVideo;
            data.vo_to_dot1p = $scope.uplink.eightVoice;

            data.dscp_to_bk = $scope.downlink.dscpBg;
            data.dscp_to_be = $scope.downlink.dscpBe;
            data.dscp_to_vi = $scope.downlink.dscpVideo;
            data.dscp_to_vo = $scope.downlink.dscpVoice;
            data.dot1p_to_bk = $scope.downlink.eightBg;
            data.dot1p_to_be = $scope.downlink.eightBe;
            data.dot1p_to_vi = $scope.downlink.eightVideo;
            data.dot1p_to_vo = $scope.downlink.eightVoice;

            var operatorMsg ='wmm_log_params_modify';

            batchSyncConfig.request("put", "/wlan/" + ssid + "/wmm/confParams", null, data, function() {
                $scope.isWmmEdit = false;
                $scope.isWmm = true;
                $scope.queryWmmParam(ssid);
            },null,operatorMsg);
        };

        /**
         * WMM uplink dscp
         */
        $scope.uplinkdscp = function(value,index) {
            var patten = /^\d+$/g;
            if(patten.test(value)) {
                if (value < 0 || value > 63) {
                    $scope.validFlag = true;
                    $scope.uplinkdscp_info = $translate.instant("enterMustBe63");
                    uplink_dscp(false,index);

                } else {
                    $scope.validFlag = false;
                    uplink_dscp(true,index);

                }
            }else{
                $scope.validFlag = true;
                $scope.uplinkdscp_info = $translate.instant("enterNotMatch");
                uplink_dscp(false,index);

            }
        }
        function uplink_dscp(flag,index){
            switch (index) {
                case 1:
                    $scope.isFormat_1 = !flag;
                    break;
                case 2:
                    $scope.isFormat_2 = !flag;
                    break;
                case 3:
                    $scope.isFormat_3 = !flag;
                    break;
                case 4:
                    $scope.isFormat_4 = !flag;
                    break;
            }
        }

        /**
         * WMM uplink 802.1
         */
        $scope.uplinkEight = function (value,index) {
            var patten = /^\d+$/g;
            if(patten.test(value)){
                if(value < 0 || value > 7){
                    $scope.validFlag = true;
                    $scope.uplinkeight_info = $translate.instant("enterMustBe7");
                    uplink_eight(false,index);

                }else{
                    $scope.validFlag = false;
                    uplink_eight(true,index);
                }
            }else{
                $scope.validFlag = true;
                $scope.uplinkeight_info = $translate.instant("enterNotMatch");
                uplink_eight(false,index);
            }

        }

        function uplink_eight(flag,index){
            switch(index){
                case 1:
                    $scope.isEightFormat_1 = !flag;
                    break;
                case 2:
                    $scope.isEightFormat_2 = !flag;
                    break;
                case 3:
                    $scope.isEightFormat_3 = !flag;
                    break;
                case 4:
                    $scope.isEightFormat_4 = !flag;
                    break;
            }
        }

        /**
         * WMM downlink dscp
         */
        $scope.downlink_msgInfo = "";
        $scope.downlink_eight_msgInfo = "";
        $scope.downlinkdscp = function (value,index) {
            //the format of wmm downlink dscp
            var patten = /^\d+(,\d+)*$/g;
            if(patten.test(value)){//the value match format
                var value_array = value.split(",");
                if(value_array.length> 8 || value_array.length== 0){//the length of value more then eight or less 0
                    $scope.validFlag = true;
                    $scope.downlink_msgInfo = $translate.instant("enterMostEight");
                    downlink_dscp(false,index);
                }else{
                    $scope.downlink_msgInfo = $translate.instant("enterMustBe63");
                    for(var i=0;i<value_array.length;i++){
                        var number = parseInt(value_array[i]);
                        if(number>63 || number<0){//the number more then 63 or less then 0
                            $scope.validFlag = true;
                            downlink_dscp(false,index)

                        }else{//the number is true ,and hide the title info
                            $scope.validFlag = false;
                            downlink_dscp(true,index)

                        }
                    }
                }
            }else{//the value does not match format
                $scope.validFlag = true;
                $scope.downlink_msgInfo = $translate.instant("enterNotMatch");
                downlink_dscp(false,index)

            }
        }

        function downlink_dscp(flag,index){
            switch (index){
                case 1:
                    $scope.isDownFormat_1 = !flag;
                    break;
                case 2:
                    $scope.isDownFormat_2 = !flag;
                    break;
                case 3:
                    $scope.isDownFormat_3 = !flag;
                    break;
                case 4:
                    $scope.isDownFormat_4 = !flag;
                    break;
            }
        }

        /**
         * WMM downlink 802.1
         * @param value
         * @param index
         */
        $scope.downlinkEight = function (value,index) {
            //the format of wmm downlink dscp
            var patten = /^\d+(,\d+)*$/g;
            if(patten.test(value)){//the value match format
                var value_array = value.split(",");
                if(value_array.length> 8 || value_array.length== 0){//the length of value more then eight or less 0
                    $scope.downlink_eight_msgInfo = $translate.instant("enterMostEight");
                    $scope.validFlag = true;
                    downlink_eight(false,index)

                }else{
                    $scope.downlink_eight_msgInfo = $translate.instant("enterMustBe7");
                    for(var i=0;i<value_array.length;i++){
                        var number = parseInt(value_array[i]);
                        if(number>7 || number<0){//the number more then 63 or less then 0
                            $scope.validFlag = true;
                            downlink_eight(false,index)

                        }else{//the number is true ,and hide the title info
                            $scope.validFlag = false;
                            downlink_eight(true,index)

                        }
                    }
                }
            }else{//the value does not match format
                $scope.downlink_eight_msgInfo =$translate.instant("enterNotMatch");
                $scope.validFlag = true;
                downlink_eight(false,index)

            }
        }


        function downlink_eight(flag,index){
            switch (index){
                case 1:
                    $scope.isDownEightFormat_1 = !flag;
                    break;
                case 2:
                    $scope.isDownEightFormat_2 = !flag;
                    break;
                case 3:
                    $scope.isDownEightFormat_3 = !flag;
                    break;
                case 4:
                    $scope.isDownEightFormat_4 = !flag;
                    break;
            }
        }

        /**
         * reset wmm config
         */
        $scope.wmmReset = function () {

            $scope.uplink = {
                dscpBg: '10',
                dscpBe: '0',
                dscpVideo: '40',
                dscpVoice: '46',
                eightBg:'1',
                eightBe: '0',
                eightVideo: '4',
                eightVoice: '6'
            };
            $scope.downlink = {
                dscpBg: "2,10",
                dscpBe: "0,18",
                dscpVideo: "26,34,40",
                dscpVoice: "46,48,56",
                eightBg: "1,2",
                eightBe: "0,3",
                eightVideo: "4,5",
                eightVoice: "6,7"
            };
            $scope.saveWmmInfo();
        }



        //add wlan ssid format
        $scope.codeDetailStart = false;
        $scope.codeDetailEnd = "";
        $scope.isDetailFormat = false;
        $scope.isDetailTrue = true;
        $scope.changeWlanName = function (value) {

            if(value!= null &&value!=""){
                var str = value.substring(0,1);
                if(str == "*"||str == "."||str == "\\"){
                    $scope.codeDetailStart = true;
                    $scope.codeDetailEnd =$translate.instant("canNotBegin");
                    $scope.isDetailFormat = true;
                    $scope.isDetailTrue = true;
                }else{
                    $scope.codeDetailStart = false;
                    $scope.isDetailFormat = false;
                    $scope.isDetailTrue = false;
                }
                var str_temp = value.substring(value.length-1,value.length);
                if(!$scope.codeDetailStart &&str_temp == "\\"){
                    $scope.codeDetailEnd =$translate.instant("canNotEnd");
                    $scope.isDetailFormat = true;
                    $scope.isDetailTrue = true;
                }
                var reg=/\s+/;
                var result =  reg.test(value);
                console.log(result);
                if(result){
                    $scope.codeDetailStart = true;
                    $scope.codeDetailEnd =$translate.instant("canNotBlanks");
                    $scope.isDetailFormat = true;
                    $scope.isDetailTrue = true;
                }

            }else{
                $scope.isDetailFormat = false;
                $scope.isDetailTrue = true;
            }
        }
        //edit ssid format
        $scope.codeEditStart = false;
        $scope.codeEditEnd = "";
        $scope.isEditFormat = false;
        $scope.isEditTrue = false;
        $scope.changeEditSSID = function (value) {

            if(value!= null &&value!=""){
                var str = value.substring(0,1);
                if(str == "*"||str == "."||str == "\\"){
                    $scope.codeEditStart = true;
                    $scope.codeEditEnd = $translate.instant("canNotBegin");
                    $scope.isEditFormat = true;
                    $scope.isEditTrue = true;
                }else{
                    $scope.codeEditStart = false;
                    $scope.isEditFormat = false;
                    $scope.isEditTrue = false;
                }
                var str_temp = value.substring(value.length-1,value.length);
                if(!$scope.codeEditStart &&str_temp == "\\"){
                    $scope.codeEditEnd = $translate.instant("canNotEnd");
                    $scope.isEditFormat = true;
                    $scope.isEditTrue = true;
                }
                var reg=/\s+/;
                var result =  reg.test(value);
                console.log(result);
                if(result){
                    $scope.codeEditStart = true;
                    $scope.codeEditEnd = $translate.instant("canNotBlanks");
                    $scope.isEditFormat = true;
                    $scope.isEditTrue = true;
                }
            }else{
                $scope.isEditFormat = false;
                $scope.isEditTrue = true;
            }
        }





        $scope.selecFormat = function () {
            $scope.formatSelected = this.formatSelected;
        }

    }]);