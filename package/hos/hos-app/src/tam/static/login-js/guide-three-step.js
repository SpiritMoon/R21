angular.module('login')
    .controller("threeStepCtrl", ['$scope', '$modal', '$modalInstance', 'toastr', 'wizardService', 'batchSyncConfig','regularExpression', 'hanCrypto','$translate', function($scope, $modal, $modalInstance, toastr, wizardService, batchSyncConfig, regularExpression, hanCrypto,$translate) {
        $scope.three = "";
        if(wizardService.getCountryFlag()){
            $scope.three = "3/3";
        }else{
            $scope.three = "2/2";
        }
        $scope.regularExpression = regularExpression;

        //redis switch
        $scope.redisSwitch = {isSwitch:false};
        $scope.isRedisShow = false;
        $scope.redisChange = function (isTRUE) {

            if(isTRUE){
                $scope.isRedisShow = true;
            }else{
                $scope.isRedisShow = false;
            }
        }



        //wlan band initialization band value
        $scope.band = {
            TwoG: true,
            FiveG: true
        };

        //when the country code is CS ,the 2G is hidden
        $scope.isTwoG = true;
        $scope.countryCode = wizardService.getCountryFlag();
        if($scope.countryCode == "CS"){
            $scope.band = {TwoG: false,FiveG: true};
            $scope.isTwoG = false;
        }

        //wizard object
        $scope.wizardInfo = {
            "ssid": "",
            "securityType": "",
            "key": "",
            "keyConfirm": "",
            "band": "",
            "authServer": "",
            "authPort": "",
            "authSecret": "",
            "acctServer": "",
            "acctPort": "",
            "acctSecret": "",
            "username": "",
            "password": "",
            "countryCode":"",
            "captivePortal":"No",
            "timezone":"",
            "city":"",
            "fast":"false",
            "okc":"false"
        };
        //WLAN password format array
        $scope.passphraseFormatArray = [{
            id: "1",
            name: "8-63 chars"
        }, {
            id: "2",
            name: "64 Hexadecimal chars"
        }];
        //WLAN password format default value
        $scope.formatSelected = $scope.passphraseFormatArray[0];
        // do not show personal and enterprise config in initialization
        $scope.isPersonal = true;
        $scope.isEnterprise = false;
        //$scope.isCapital = false;
        //WLAN security type array
        $scope.securityTypeArray = [
            {id: "00", name: "Open", units: [ ]},
            {id: "01", name: "Personal", units: [
                {id: "0109",name: "Both(wpa &wpa2)",value:"psk-mixed+tkip+aes"},
                {id: "0107",name: "wpa2-personal",value:"psk2+aes"}

            ]},
            {id: "02", name: "Enterprise", units: [
                {id: "0209",name: "Both(wpa &wpa2)",value:"wpa-mixed+tkip+aes"},
                {id: "0207",name: "wpa2-enterprise",value:"wpa2+aes"}
            ]}];

        $scope.selectedSecurity = $scope.securityTypeArray[1];
        $scope.selectedEncryption = $scope.selectedSecurity.units[0];
        $scope.formatSelected = $scope.passphraseFormatArray[0];
        $scope.disabledSecurity = false;
        $scope.disabledEncryption = false;


        // change security type
        $scope.changeSecurityType = function() {

            if (this.selectedSecurity.id == "00") {
                $scope.isPersonal = false;
                $scope.isEnterprise = false;
                //$scope.isCapital = true;

            }else if(this.selectedSecurity.id == "01"){
                $scope.isPersonal = true;
                $scope.isEnterprise = false;
                //$scope.isCapital = false;
                this.selectedEncryption = this.selectedSecurity.units[0];

            }else if(this.selectedSecurity.id == "02"){
                $scope.isPersonal = false;
                $scope.isEnterprise = true;
                $scope.isRedisShow = false;
                $scope.redisSwitch.isSwitch = false;
                //$scope.isCapital = false;
                this.selectedEncryption = this.selectedSecurity.units[0];
            }
        };

        //the operation after saving  contains upd password and create wlan
        //the operation after save wlan information
        $scope.save = function() {
            $scope.wizardInfo.countryCode = wizardService.getCountry().countryCode;
            $scope.wizardInfo.securityType = this.selectedSecurity.name;
            //undefined
            if (typeof(this.selectedEncryption) == undefined) {} else {
                $scope.wizardInfo.encryption = this.selectedEncryption.value;
            }

            //set band value
            if ($scope.band.TwoG && $scope.band.FiveG) {
                $scope.wizardInfo.band = "2G,5G";
            } else if ($scope.band.TwoG) {
                $scope.wizardInfo.band = "2G";
            } else if ($scope.band.FiveG) {
                $scope.wizardInfo.band = "5G";
            } else {
                toastr.info('please selected band !', '');
                return;
            }

            //username and password
            $scope.wizardInfo.username = wizardService.getUserInfo().username;
            $scope.wizardInfo.password = wizardService.getUserInfo().password;

            //timeZone & city
            $scope.wizardInfo.timezone = wizardService.getCountry().timezone;
            $scope.wizardInfo.city = wizardService.getCountry().city;
            
            if(!$scope.redisSwitch.isSwitch){
                $scope.wizardInfo.acctServer = "";
                $scope.wizardInfo.acctPort = "";
                $scope.wizardInfo.acctSecret = "";
            }

           

            //encoder key
            var encoderWizardInfo = angular.copy($scope.wizardInfo);
            encoderWizardInfo.key = hanCrypto.encoder(encoderWizardInfo.key);
            encoderWizardInfo.keyConfirm = hanCrypto.encoder(encoderWizardInfo.keyConfirm);
            encoderWizardInfo.authSecret = hanCrypto.encoder(encoderWizardInfo.authSecret);
            encoderWizardInfo.acctSecret = hanCrypto.encoder(encoderWizardInfo.acctSecret);

            //batch config
            batchSyncConfig.request('post', '/other/wizard', null, encoderWizardInfo, function(flag) {
                $modalInstance.dismiss('cancel');

                if('logout' == flag){
                    $modal.open({
                        templateUrl: 'logout-prompt.html',
                        controller: "login-logoutPromptCtrl",
                        size: 'md',
                        backdrop: 'static',
                        keyboard: false
                    });
                }else{
                    var instance = $modal.open({
                        templateUrl: 'guide-complete.html',
                        controller: "completeCtrl",
                        size: 'md',
                        backdrop: 'static',
                        resolve: {
                            wlanName : function(){
                                return $scope.wizardInfo.ssid;
                            }
                        }
                    });
                }
            });
        };

        //ssid format
        $scope.codeDetailStart = false;
        $scope.codeDetailEnd = "";
        $scope.isDetailFormat = false;
        $scope.isDetailTrue = true;
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
                var reg=/\s+/;
                var result =  reg.test(value);
                if(result){
                    $scope.codeDetailStart = true;
                    $scope.codeDetailEnd = $translate.instant("canNotBlanks");
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
    .directive('integerport',[function(){
    return {
        restrict: 'A',
        link:function(scope,ele,attrs){
            ele.bind('paste',function(event){
                var e=event || window.event;
                if(e.charCode){
                    e.preventDefault();
                }else{
                    e.returnValue=false;
                }
            });
            ele.bind("keydown",function(event){
                var e=event || window.event;
                if(e.keyCode == 13) {
                    e.keyCode = 9;
                }else if(e.charCode == 13){
                    e.charCode=9;
                }
            });
            ele.bind("keypress",function(event){
                var e=event || window.event;
                if(e.charCode && (e.charCode<48 || e.charCode >57)){
                    e.preventDefault();
                }
                if (e.keyCode<48 || e.keyCode>57) {
                    e.returnValue=false;
                }
            });
        }
    }}]);