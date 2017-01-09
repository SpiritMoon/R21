angular.module('common', [])
    .controller("aboutContronller", ['$scope', '$modalInstance', 'authentifiedRequest', 'InterService', function($scope, $modalInstance, authentifiedRequest, InterService) {
        $scope.skin = InterService.skin;
        $scope.aboutInfo = {
            "name": '',
            "softVersion": '',
            "website": '',
            "legal": '',
            "countryCode":''
        };
        //cancel dosomething
        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.query = function() {
            authentifiedRequest.get('/other/systemInfo', null, function(response) {
                if (response.success) {
                    var data = response.result;
                    $scope.aboutInfo.name = data.HanletName;
                    $scope.aboutInfo.softVersion = data.SoftwareVer;
                    $scope.aboutInfo.website = data.Website;
                    $scope.aboutInfo.legal = data.Legal;
                    $scope.aboutInfo.countryCode = data.countryCode;
                }
            }, function() {});
        };

        //
        $scope.query();

    }]);