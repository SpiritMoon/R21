angular.module('login')
    .controller("welcomeCtrl",['$rootScope','$scope','$modalInstance','$modal', function($rootScope,$scope,$modalInstance,$modal){
        $scope.welcomeNext = function(){
            $modalInstance.dismiss('cancel');
            $rootScope.modal_instance = $modal.open({
                templateUrl: 'guide-first-step.html',
                controller:"firstStepCtrl",
                size: 'md',
                backdrop: 'static',
                keyboard:false
            });
        }
    }])
;

