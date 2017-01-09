angular.module('wlan')
    .controller("wlanConfContronller", ['$scope', '$modalInstance','$translate', 'InterService', 'batchSyncConfig', 'toastr', 'hanCrypto', 'wlans', function($scope, $modalInstance, $translate,InterService, batchSyncConfig, toastr, hanCrypto, wlans) {
    	$scope.skin = InterService.skin;

        /**
         * WLAN parameter init
         */
        $scope.wlanList = wlans;

        $scope.wlanInfo = {"maxClients":64,
            "probeThreshold":0,
            "hidden":"No",
            "enable":"Yes",
            "captivePortal":"No",
            "vlanId":0,
            "upstreamLimit":0,
            "downstreamLimit":0,
            "securityType":"",
            "encryption":"",
            "authPort" : 1812,
            "acctPort" : 1813};

        $scope.isWlan = true;
        $scope.isAdvanceWlan = false;
        $scope.isPersonal = true;
        $scope.isEnterprise = false;
        $scope.isCapital = false;
	    $scope.InterService = InterService;
	 
        //control select disabled
        $scope.disabledSecurity = false;
        $scope.disabledEncryption = false;


        //security type
        $scope.securityTypeArray=[
            {id: "00", name: "Open", units: [ ]},
            {id: "01", name: "Personal", units: [
                {id: "0109",name: "Both(wpa &wpa2)",value:"psk-mixed+tkip+aes"},
                {id: "0107",name: "wpa2-personal",value:"psk2+aes"}

            ]},
            {id: "02", name: "Enterprise", units: [
                {id: "0209",name: "Both(wpa &wpa2)",value:"wpa-mixed+tkip+aes"},
                {id: "0207",name: "wpa2-enterprise",value:"wpa2+aes"}
            ]}];


        //pass format
        $scope.passphraseFormatArray = [{id:"1",name:"8-63 chars"},{id:"2",name:"64 Hexadecimal chars"}];

        $scope.selectedSecurity = $scope.securityTypeArray[1];
        $scope.selectedEncryption = $scope.selectedSecurity.units[0];
        $scope.formatSelected = $scope.passphraseFormatArray[0];

        $scope.band = { twoG:true, fiveG:true };
        //when the country code is CS ,the 2G is hidden
        $scope.isTwoG = true;
        $scope.countryCode = InterService.getCountryCode();
        if($scope.countryCode == "CS"){
            $scope.band = {twoG: false,fiveG: true};
            $scope.isTwoG = false;
        }

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




        //add wlan simple
        $scope.saveWlanInfo = function() {
            if(($scope.band.twoG) && ($scope.band.fiveG)){
                $scope.wlanInfo.band = "2G,5G";
            }else if($scope.band.twoG){
                $scope.wlanInfo.band = "2G";
            }else if($scope.band.fiveG){
                $scope.wlanInfo.band = "5G";
            }else{
                toastr.info($translate.instant("pleaseSelectedBand"), '');
                return;
            }

            $scope.wlanInfo.securityType = this.selectedSecurity.name;
            if($scope.securityTypeArray[0].name !== $scope.wlanInfo.securityType){
                $scope.wlanInfo.encryption = this.selectedEncryption.value;
            }

            if(!$scope.redisSwitch.isSwitch){
                $scope.wlanInfo.acctServer = "";
                $scope.wlanInfo.acctPort = "";
                $scope.wlanInfo.acctSecret = "";
            }

            addWlan(false);
        };

        //close button
        $scope.cancel = function() {
            $modalInstance.close();
        };

        $scope.showSimple = function(){
            $scope.isWlan = true;
            $scope.isAdvanceWlan = false;
        };


        /**
         * the down is detail advance config
         */
        //show wlan advance page
        $scope.showAdvance = function(){
            $scope.isWlan = false;
            $scope.isAdvanceWlan = true;
        };

        //network type

        //switch securityType
        $scope.changeSecurity = function () {
            if (this.selectedSecurity.id == "00") {
                $scope.isPersonal = false;
                $scope.isEnterprise = false;
                $scope.isCapital = true;

            }else if(this.selectedSecurity.id == "01"){
                $scope.isPersonal = true;
                $scope.isEnterprise = false;
                $scope.isCapital = false;
                this.selectedEncryption = this.selectedSecurity.units[0];

            }else if(this.selectedSecurity.id == "02"){
                $scope.isPersonal = false;
                $scope.isEnterprise = true;
                $scope.isCapital = false;
                $scope.isRedisShow = false;
                $scope.redisSwitch.isSwitch = false;
                this.selectedEncryption = this.selectedSecurity.units[0];
            }
        };
        //add advance wlan
        $scope.saveWlanAdvance = function () {
            if(($scope.band.twoG) && ($scope.band.fiveG)){
                $scope.wlanInfo.band = "2G,5G";
            }else if($scope.band.twoG){
                $scope.wlanInfo.band = "2G";
            }else if($scope.band.fiveG){
                $scope.wlanInfo.band = "5G";
            }else{
                toastr.info($translate.instant("pleaseSelectedBand"), '');
                return;
            }

            $scope.wlanInfo.securityType = this.selectedSecurity.name;
            if($scope.securityTypeArray[0].name !== $scope.wlanInfo.securityType){
                $scope.wlanInfo.encryption = this.selectedEncryption.value;
            }

            if(!$scope.redisSwitch.isSwitch){
                $scope.wlanInfo.acctServer = "";
                $scope.wlanInfo.acctPort = "";
                $scope.wlanInfo.acctSecret = "";
            }
            addWlan(true);
        };

        $scope.isWlanExist = function(wlanSsid, wlanList){
            for(var i=0; i<wlanList.length; i++) {
                if(wlanSsid == wlanList[i].ssid){
                    return true;
                }
            }
            return false;
        };

        function addWlan(isAdvance){
            if($scope.isWlanExist($scope.wlanInfo.ssid, $scope.wlanList)){
                toastr.info($translate.instant("wlanAlreadyExist1")+$scope.wlanInfo.ssid+$translate.instant("wlanAlreadyExist2"), '');
            }else{
                var operatorMsg;
                if(isAdvance){
                    var url = "/advanceWlan";
                    operatorMsg = "wlan_add_1";
                }else{
                    var url = "/wlan";
                    operatorMsg = "wlan_add_2";
                }

                var logtemp = $scope.wlanInfo.ssid;

                //encoder key
                var encoderWlanInfo = angular.copy($scope.wlanInfo);
                encoderWlanInfo.key = hanCrypto.encoder(encoderWlanInfo.key);
                encoderWlanInfo.keyConfirm = hanCrypto.encoder(encoderWlanInfo.keyConfirm);
                encoderWlanInfo.authSecret = hanCrypto.encoder(encoderWlanInfo.authSecret);
                encoderWlanInfo.acctSecret = hanCrypto.encoder(encoderWlanInfo.acctSecret);

                var requestParas = JSON.stringify(encoderWlanInfo);

                batchSyncConfig.request("post", url, null, requestParas, function(){
                    $modalInstance.close();
                }, null, operatorMsg, null, logtemp);
            }
        };



        //ssid format
        $scope.codeStart = false;
        $scope.codeEnd = "";
        $scope.isFormat = false;
        $scope.isTrue = false;
        $scope.changeSSID = function (value) {

            if(value!= null &&value!=""){
                var str = value.substring(0,1);
                if(str == "*"||str == "."||str == "\\"){
                    $scope.codeStart = true;
                    $scope.codeEnd = $translate.instant("canNotBegin");
                    $scope.isFormat = true;
                    $scope.isTrue = true;
                }else{
                    $scope.codeStart = false;
                    $scope.isFormat = false;
                    $scope.isTrue = false;
                }
                var str_temp = value.substring(value.length-1,value.length);
                if(!$scope.codeStart &&str_temp == "\\"){
                    $scope.codeEnd = $translate.instant("canNotEnd");
                    $scope.isFormat = true;
                    $scope.isTrue = true;
                }
                var reg=/\s+/;
                var result =  reg.test(value);
                console.log(result);
                if(result){
                    $scope.codeStart = true;
                    $scope.codeEnd = $translate.instant("canNotBlanks");
                    $scope.isFormat = true;
                    $scope.isTrue = true;
                }

            }else{
                $scope.isFormat = false;
                $scope.isTrue = true;
            }
        }




        //ssid format
        $scope.codeDetailStart = false;
        $scope.codeDetailEnd = "";
        $scope.isDetailFormat = false;
        $scope.isDetailTrue = false;
        $scope.changeDetailSSID = function (value) {

            if(value!= null &&value!=""){
                var str = value.substring(0,1);
                if(str == "*"||str == "."||str == "\\"){
                    $scope.codeDetailStart = true;
                    $scope.codeDetailEnd = $translate.instant("canNotBegin");
                    $scope.isDetailFormat = true;
                    $scope.isDetailTrue = true;
                }else{
                    $scope.codeDetailStart = false;
                    $scope.isDetailFormat = false;
                    $scope.isDetailTrue = false;
                }
                var str_temp = value.substring(value.length-1,value.length);
                if(!$scope.codeDetailStart &&str_temp == "\\"){
                    $scope.codeDetailEnd = $translate.instant("canNotEnd");
                    $scope.isDetailFormat = true;
                    $scope.isDetailTrue = true;
                }
            }else{
                $scope.isDetailFormat = false;
                $scope.isDetailTrue = true;
            }
        }



        $scope.selecFormat = function () {
            $scope.formatSelected = this.formatSelected;
        }
    }])
    .directive("greenSlider", [function() {
        var linkFun = function($scope, element, attrs) {
            $slider = jQuery(element);
            var option = attrs;
            var tryPrseInt = function(key, option) {
                if (option[key]) {
                    option[key] = parseInt(option[key]);
                }
            };

            tryPrseInt("min", option);
            tryPrseInt("max", option);
            tryPrseInt("step", option);

            option = jQuery.extend({
                value: $scope[option.ngModel],
                change: function(event, ui) {
                    if (attrs.ngModel && ui.value != $scope[attrs.ngModel]) {
                        var express = attrs.ngModel + ' = ' + ui.value;
                        $scope.$apply(express);
                        if (attrs.ngChange) {
                            $scope.$eval(attrs.ngChange);
                        }
                    }
                }
            }, option);
            $slider.slider(option);
            //back
            if (option.ngModel) {
                $scope.$watch(option.ngModel, function(val) {
                    if (val != $slider.slider("value")) {
                        $slider.slider("value", val);
                    }
                });
            }
        };
        return {
            restrict: 'E',
            replace: true,
            transclude: false,
            template: '<div />',
            link: linkFun
        };
    }])
    .filter("securityTypeFilter", [function() {
        var filterfun = function(value) {
            switch(value){
                case 10:
                    return "open";
                    break;
                case 20:
                    return "WPA-2Personal";
                    break;
                case 30:
                    return "WPA-Personal(Both TKIP and AES Encryption)";
                    break;
                case 40:
                    return "WPA-Personal(TKIP Encryption only)";
                    break;
                case 50:
                    return "WPA-Personal(AES Encryption only)";
                    break;
                case 60:
                    return "Static WEP";
                    break;
                case 70:
                    return "WPA-2Enterprise";
                    break;
                case 80:
                    return "WPA Enterprise";
                    break;
            }
        };
        return filterfun;
    }]);