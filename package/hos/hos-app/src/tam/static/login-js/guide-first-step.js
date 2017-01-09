angular.module('login')
.controller("firstStepCtrl",['$translate', '$scope','$modal','$modalInstance','toastr','wizardService','regularExpression', function($translate, $scope,$modal,$modalInstance,toastr,wizardService,regularExpression){
    $scope.updFlag = true;
    $scope.updateParam = {"password":"","confirm":""};
    $scope.regularExpression = regularExpression;
    $scope.first = "";
    if(wizardService.getCountryFlag()){
        $scope.first = "1/3";
    }else{
        $scope.first = "1/2";
    }
    $scope.firstStepOk = function(){
     //check username and password are not null
        if($scope.updateParam.password == "" || $scope.updateParam.confirm == ""){

            var info = $translate.instant("login_log_password_notnull");
            toastr.info(info);
            return;
        }
		if($scope.updateParam.password == "admin"){
            toastr.info($translate.instant("log_update_password"));
            return ;
        }
        
        wizardService.setUserpassword(hex_md5($scope.updateParam.password).toLowerCase());
        $modalInstance.dismiss('cancel');
        if(wizardService.getCountryFlag()){
            var instance = $modal.open({
                templateUrl: 'guide-second-step.html',
                controller:"secondStepCtrl",
                size: 'md',
                backdrop: 'static',
                keyboard:false
            });
        }else{
            var instance = $modal.open({
                templateUrl: 'guide-three-step.html',
                controller:"threeStepCtrl",
                size: 'md',
                backdrop: 'static',
                keyboard:false
            });
        }

    };
           
}])
;

