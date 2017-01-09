angular.module("wlan", [])
    .filter("wlanEnableFilter", [function() {
        var filterfun = function(value) {
            switch(value){
                case true:
                    return "On";
                    break;
                case false:
                    return "Off";
                    break;
            }
        };
        return filterfun;
    }])
    .controller("wlanController", ['$scope', 'singleModal', 'authentifiedRequest', 'batchSyncConfig', 'clientService', 'monitorService', 'hanCrypto','$translate', function($scope, singleModal, authentifiedRequest, batchSyncConfig, clientService, monitorService, hanCrypto,$translate) {
        /**
         * WLAN parameter init
         */
        $scope.wlans = {};

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
        $scope.titleWidth="";
        $scope.wlanManagement.query = function() {
            var params = {};

            authentifiedRequest.get("/wlans", params, function(response, status) {
                if (status == 200 && null != response && response.success){
                    //decoder key
                    for (var i = 0; i < response.result.wlanList.length; i++) {
                        response.result.wlanList[i].key = hanCrypto.decoder(response.result.wlanList[i].key);
                        response.result.wlanList[i].authSecret = hanCrypto.decoder(response.result.wlanList[i].authSecret);
                        response.result.wlanList[i].acctSecret = hanCrypto.decoder(response.result.wlanList[i].acctSecret);
                    }

                    $scope.wlanInfo = response.result;
                    $scope.wlans = $scope.wlanInfo.wlanList;
                    for (var i = 0; i < $scope.wlans.length; i++) {
                        $scope.wlanClients = clientService.getWlanClient($scope.wlans[i].ssid);

                        if(null != $scope.wlanClients){
                            $scope.wlans[i].clients = $scope.wlanClients.length;
                        }else {
                            $scope.wlans[i].clients = 0;
                        }
                    }
                    if($scope.wlans.length>5){
                        $scope.titleWidth="padding-right:17px;";
                    }else{
                        $scope.titleWidth="";
                    }
                }
            }, function() {
                //console.info('query wlan list error!');
            });
        };

        /**
         * call initialization method
         */
        $scope.wlanManagement.query();

        /**
         * show add wlan div
         */
        $scope.modal = null;
        $scope.newWlan = function() {
            singleModal.open({
                templateUrl: 'wlan/wlan-conf.html',
                controller: 'wlanConfContronller',
                size: 'md',
                backdrop: true,
                resolve: {
                    wlans : function(){
                        return $scope.wlans;
                    }
                }
            },function() {
                $scope.wlanManagement.query();
            },function() {
                $scope.wlanManagement.query();
            });
        };

        /**
         * show wlan list page
         */
        $scope.showWlanList = function() {
            singleModal.open({
                templateUrl: 'wlan/wlan-list.html',
                controller: 'listContronller',
                size: 'lg',
                backdrop: true,
                resolve: {
                    wlans : function(){
                        return $scope.wlans;
                    }
                }
            },function(result) {
                $scope.wlanManagement.query();
            },function(reason) {
                $scope.wlanManagement.query();
            });
        };

        /**
         * config wlan status
         */
        $scope.configStatus = function(item) {
            //encoder key
            item.key = hanCrypto.encoder(item.key);
            item.authSecret = hanCrypto.encoder(item.authSecret);
            item.acctSecret = hanCrypto.encoder(item.acctSecret);

            var requestParas = JSON.stringify(item);
            var operatorMsg;
            if(item.enable){
                operatorMsg = "wlan_edit_status_1";
            }else{
                operatorMsg = "wlan_edit_status_2" ;
            }

            var logtemp = item.ssid;

            batchSyncConfig.request("put", "/wlanStatus/" + $scope.urlEscape(item.ssid), null, requestParas, function() {
                $scope.wlanManagement.query();
            }, null, operatorMsg, null, logtemp);
        };

        /**
         * switch monitor object
         */
        $scope.showMonitorData = function(item) {
            var title = $translate.instant("ClusterSSID") + item.ssid;
            monitorService.changeObser('wlan', item.ssid, title);
            $scope.clientManagement.changeClient('wlan', item.ssid);
        };
    }])
    .directive('hover',['InterService',function(InterService){
    return {
        restrict: 'A',
        link:function(scope,ele,attrs){
            ele.bind('mouseover',function(attrs){
               /* First level menu*/
             if(ele.attr('mnuelevel') == '1'){
                 /* If it is blue*/
                 if(InterService.skin.isBlue){
                     ele.css('background-color','#608ebd');
                     /* If it is purple*/
                 }else if(InterService.skin.isPurple){
                     ele.css('background-color','#9482a5');
                 }/*Two level menu  */
             }else if(ele.attr('mnuelevel') == '2'){
                 /* If it is blue*/
                 if(InterService.skin.isBlue){
                     ele.css('background-color','#c4dff1');
                     /* If it is purple*/
                 }else if(InterService.skin.isPurple){
                     ele.css('background-color','#ddcfe0');
                 }
             }else if(ele.attr('mnuelevel') == '0'){
                 /* If it is blue */
                 if(InterService.skin.isBlue){
                     ele.css('background-color','#608ebd');
                  /*  If it is purple */
                 }else if(InterService.skin.isPurple){
                     ele.css('background-color','#9482a5');
                 }
             }
            });
            ele.bind('mouseleave',function(){
                if(ele.attr('mnuelevel') != '0'){
                    ele.removeAttr('style');
                }  else{
                   /* because div hava style="padding:0px";*/
                    ele.attr("style","padding:0px;");
                }
            });
        }
    }
}]);