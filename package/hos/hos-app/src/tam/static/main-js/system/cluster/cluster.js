angular.module("system",[])
    .service('ClusterService', ['authentifiedRequest', function(authentifiedRequest) {
        var vm = this;
        vm.ClusterinfoSer = {};
        vm.getClusterinfoSer = function() {
            return vm.ClusterinfoSer;
        }
        vm.setClusterinfoSer = function(x) {
            vm.ClusterinfoSer = x;
        }
        vm.HttpClusterInfo = function(callbackFuction) {
            authentifiedRequest.get("/getcluster", null, function(data) {
                if (data != null && data.success) {
                    vm.ClusterinfoSer = data.result;
                    if(callbackFuction != null){
                        callbackFuction();
                    }
                } else {
                    console.info('haps fail');
                }
            }, function() {
                console.info('haps error');
            });
        }

    }])
    .controller("clusterController", ['$scope','singleModal','authentifiedRequest','ClusterService', function($scope,singleModal,authentifiedRequest,ClusterService) {

        $scope.toggleManager.clusterInit = function(){
            ClusterService.HttpClusterInfo(null);
        }
        $scope.toggleManager.clusterInit();
        $scope.$watch('ClusterService.ClusterinfoSer', function(newVal, oldVal) {
            console.log(newVal !== oldVal);
            if (newVal !== oldVal) {
                $scope.clusterInfo = ClusterService.getClusterinfoSer();
            }
        }, true);


        $scope.showCluster = function () {
            singleModal.open({
                templateUrl: 'system/cluster/cluster-config.html',
                controller: 'clusterConfController',
                size: 'lg',
                backdrop: true
            });
        };

    }])
    .filter('userisEnable',[function(){
        var filterfun = function(value){
            switch (value){
                case '0':
                    return 'Disabled';
                    break;
                case '1':
                    return 'Enable ';
                    break;
            }
        };
        return filterfun;
    }])

;


