angular.module('login')
.controller("httpsCtrl",['$translate', '$scope','$modal','$modalInstance','toastr','wizardService','regularExpression','lockScreen','$http','$location', function($translate, $scope,$modal,$modalInstance,toastr,wizardService,regularExpression,lockScreen,$http,$location){
    //download certificate
    $scope.downloadCertificate = function () {
        var url  = wizardService.getProtocol()+"://" + wizardService.getIP() + ":"+wizardService.getPort()+"/downloadCertificate";
        var filename = "CAhan.crt";
        var filenameInfo = "ALE OmniAccess.CRT";
        $http({
            method: 'put',
            url: url,
            params:{name:filename},
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        }).success(function(data, status, headers) {
            lockScreen.unlock();

            if(data == null || data == ''){
            }else{
                if(typeof(data.success) == "undefined"){
                    saveFile(data, headers, filenameInfo);
                    toastr.info($translate.instant("downloadCertificateSuccess"), '');
                }else{
                    toastr.info($translate.instant(data.msg), '');
                }
            }

        }).error(function() {
            /**
             * unlock screen
             */
            lockScreen.unlock();
            toastr.warning($translate.instant("log_backendServer_error"), '');
        });
    }

    //go  to  https  login page
    $scope.goToHttpsLogin = function () {
        window.location.href = "https://"+wizardService.getIP()+"/static/login.html";
    }


    function saveFile(data, headers, filename){
        var octetStreamMime = 'application/octet-stream';
        var success = false;
        headers = headers();
        var contentType = headers['content-type'] || octetStreamMime;
        try{
            //console.log("Trying saveBlob method ...");
            var blob = new Blob([data], { type: contentType });
            if(navigator.msSaveBlob) {
                navigator.msSaveBlob(blob, filename);
            }else{
                var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
                if(saveBlob === undefined){
                    throw "Not supported";
                }else{
                    saveBlob(blob, filename);
                }
                //console.log("saveBlob succeeded");
                success = true;
            }
        }catch(ex){
            //console.log("saveBlob method failed with the following exception:");
            //console.log(ex);
        }
        if(!success){
            var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
            if(urlCreator){
                var link = document.createElement('a');
                if('download' in link){
                    try {
                        //console.log("Trying download link method with simulated click ...");
                        var blob = new Blob([data], { type: contentType });
                        var url = urlCreator.createObjectURL(blob);
                        link.setAttribute('href', url);
                        link.setAttribute("download", filename);
                        var event = document.createEvent('MouseEvents');
                        event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
                        link.dispatchEvent(event);
                        //console.log("Download link method with simulated click succeeded");
                        success = true;
                    } catch(ex) {
                        //console.log("Download link method with simulated click failed with the following exception:");
                        //console.log(ex);
                    }
                }
                if(!success){
                    try{
                        //console.log("Trying download link method with window.location ...");
                        var blob = new Blob([data], { type: octetStreamMime });
                        var url = urlCreator.createObjectURL(blob);
                        window.location = url;
                        //console.log("Download link method with window.location succeeded");
                        success = true;
                    }catch(ex){
                        //console.log("Download link method with window.location failed with the following exception:");
                        //console.log(ex);
                    }
                }
            }
        }
        if(!success){
            //console.log("No methods worked for saving the arraybuffer, using last resort window.open");
            window.open(httpPath, '_blank', '');
        }
    };

}])
;

