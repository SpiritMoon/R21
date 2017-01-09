/**
 * Created by Administrator on 16-7-7.
 */

angular.module('main')
    .directive("highLight", [function(){
        return {
            restrict: "A",
            link: function(scope, element, attrs){
                element.bind("click", function(){
                    element.addClass("highLight");
                    element.siblings().removeClass("highLight");
                });
            }
        }
    }])
    .directive("monitorHighLight",[function(){
        return {
            restrict: "A",
            link: function(scope, element, attrs){
                element.bind("click", function(){
                    var current_module = attrs.monitorHighLight.trim();

                    if(current_module == "ap"){
                        element.addClass("highLight");
                        element.parent().siblings().children().removeClass("highLight");
                        
                        $("#wlan_view_table tr").removeClass("highLight");
                        $("#client_view_table tr").removeClass("highLight");
                    }else if(current_module == "wlan"){
                        element.addClass("highLight");
                        element.siblings().removeClass("highLight");

                        $("#ap_view_table tr").removeClass("highLight");
                        $("#client_view_table tr").removeClass("highLight"); 
                    }else if(current_module == "client"){
                        element.addClass("highLight");
                        element.siblings().removeClass("highLight");

                        $("#wlan_view_table tr").removeClass("highLight");
                        $("#ap_view_table tr").removeClass("highLight");
                    }else if(current_module == "cluster"){
                        $("#wlan_view_table tr").removeClass("highLight");
                        $("#ap_view_table tr").removeClass("highLight");
                        $("#client_view_table tr").removeClass("highLight");
                    }
                })
                
            }
        }
    }])
;
