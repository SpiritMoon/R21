/**
 * Created by Administrator on 16-7-15.
 */
angular.module('main')
    .directive("disableSpace", [function(){
        return {
            restrict: "A",
            link: function(scope, element, attrs){
                element.bind("keypress", function(){
                    if(event.keyCode == 32){
                        event.returnValue = false;
                    }
                });
            }
        }
    }])
;