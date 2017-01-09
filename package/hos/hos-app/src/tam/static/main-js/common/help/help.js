angular.module('common')
    .controller("helpContronller", ['$modalInstance', function( $modalInstance) {
        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

    }]);
