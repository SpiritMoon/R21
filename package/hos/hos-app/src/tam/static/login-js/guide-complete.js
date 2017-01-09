angular.module('login')
    .controller("completeCtrl",['$rootScope','$scope','wlanName', function($rootScope,$scope,wlanName){
        $scope.wlanName = wlanName;
        $scope.complete = function() {
            //re-login
            window.location.href = "login.html"
        };
    }])
;

