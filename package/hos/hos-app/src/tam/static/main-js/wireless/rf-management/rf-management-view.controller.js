angular.module('module.wireless.rfManagement',[])
    .controller('RfManagementViewController', ['$scope', 'singleModal', 'authentifiedRequest', 'InterService','$translate', function($scope, singleModal, authentifiedRequest, InterService, $translate) {
        /**
         * RfManagement parameter init
         */
        $scope.RF={
            "type" : "2.4G",
            "noData" : false
        };
        $scope.twoChannelData=[];
        $scope.fiveChannelData=[];

        $scope.xFunction = function() {
            return function(d) {
                return d.key;
            };
        };
        $scope.yFunction = function() {
            return function(d) {
                return d.y;
            };
        };
        $scope.toolTipContentFunction = function(){
            return function(key, x, y, e, graph) {
                var channelInfo = $translate.instant("Channel");
                var haveInfo = $translate.instant("have");
                return  '<p>' +channelInfo +'<b> ' + key + ' </b>'+ haveInfo +'<b> '+ parseInt(x)  + '</b> RF' + '</p>'
            };
        };

        /**
         * combination chart data
         */
        function getChannelData(data){
            //alert(JSON.stringify(data));
            $scope.twoChannelData=[];
            $scope.fiveChannelData=[];
            for(var i=0; i<data.length; i++){
                var channel_2g = data[i].channel_2g;
                var channel_5g = data[i].channel_5g;
                var twoChannel = new Object();
                var fiveChannel = new Object();
                if(0 == i){
                    twoChannel.key = channel_2g;
                    twoChannel.y = 1;
                    $scope.twoChannelData.push(twoChannel);

                    fiveChannel.key = channel_5g;
                    fiveChannel.y = 1;
                    $scope.fiveChannelData.push(fiveChannel);
                }else{
                    for(var two=0; two<$scope.twoChannelData.length; two++){
                        var obj2 = $scope.twoChannelData[two];
                        if(channel_2g == obj2.key){
                            obj2.y++;
                            break;
                        }
                    }
                    if(two == $scope.twoChannelData.length){
                        twoChannel.key = channel_2g;
                        twoChannel.y = 1;
                        $scope.twoChannelData.push(twoChannel);
                    }

                    for(var five=0; five<$scope.fiveChannelData.length; five++){
                        var obj5 = $scope.fiveChannelData[five];
                        if(channel_5g == obj5.key){
                            obj5.y++;
                            break;
                        }
                    }
                    if(five == $scope.fiveChannelData.length){
                        fiveChannel.key = channel_5g;
                        fiveChannel.y = 1;
                        $scope.fiveChannelData.push(fiveChannel);
                    }
                }
            }

            if("2.4G" == $scope.RF.type){
                if(0 == $scope.twoChannelData){
                    $scope.RF.noData = true;
                }else{
                    $scope.RF.noData = false;
                }
            }

            if("5G" == $scope.RF.type){
                if(0 == $scope.fiveChannelData){
                    $scope.RF.noData = true;
                }else{
                    $scope.RF.noData = false;
                }
            }
            //alert(JSON.stringify($scope.twoChannelData));
            //alert(JSON.stringify($scope.fiveChannelData));
        };

        /**
         * http request to obtain the configuration of RF
         */
        $scope.toggleManager.rfInit = function(){
            var params ={};
            var apListParams=[];

            /**
             * get ap list
             */
            var apList = InterService.getCanConfigAps();

            for(var i=0; i<apList.length; i++){
                var host = apList[i].ip;
                var url = InterService.getProtocol()+"://" + host + ":"+InterService.getPort()+"/rf";
                //var url = "http://" + host + ":8080/rf";
                authentifiedRequest.get(url, params, function(response, status){
                    if(status == 200 && null != response && response.success){
                        apListParams.push(response.result);
                    }
                    
                    if(i == apList.length){
                        getChannelData(apListParams);
                    }
                }, function(){
                    //console.info('init rf error!');
                });
            }
        };

        /**
         * open modal
         */
        $scope.modal = null;
        $scope.openConfigPage = function(){
            singleModal.open({
                templateUrl: 'wireless/rf-management/rf-management-conf.html',
                controller: 'RfManagementConfController',
                size:'lg',
                backdrop:true
            },function(result){
                $scope.toggleManager.rfInit();
            },function(reason){
                $scope.toggleManager.rfInit();
            });
        };
    }]);