angular.module('main')
    .filter("switchFilter", ['$translate', function($translate) {
        var filterfun = function(value) {
            switch(value){
                case true:
                    return $translate.instant("Open");
                    break;
                case false:
                    return $translate.instant("Close");
                    break;
            }
        };
        return filterfun;
    }]);