/**
 * Created by shensf on 2016/3/24.
 */
angular.module("module.terminal.acl",[])
    .controller("TerminalAclViewController",['$scope', '$http', 'singleModal','authentifiedRequest', function( $scope, $http, singleModal,authentifiedRequest){

        $scope.aclList = [];
        $scope.toggleManager.aclGetRule = function(){
            var params = {};
            $scope.aclList = [];
            authentifiedRequest.get("/aclrule", params, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.aclList = data.result;
                }
            },function(){
            })
        }
        /**
         *
         */
        $scope.openAclViewPageInit = function(){
            singleModal.open({
                templateUrl: 'terminal/acl/acl-conf.html',
                controller: 'TerminalAclConfController',
                size:'lg',
                backdrop:true
            },function(result) {
                $scope.toggleManager.aclGetRule();
            },function(reason) {
                $scope.toggleManager.aclGetRule();
            });

        };
    }])
;
