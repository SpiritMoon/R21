angular.module("module.terminal.authentication")
    .controller('TerminalAuthConfController', ['$scope', '$modalInstance', '$translate', 'authentifiedRequest', 'InterService', 'batchSyncConfig', 'FileUploader', 'toastr', 'hanCrypto', '$http', function($scope, $modalInstance, $translate, authentifiedRequest, InterService, batchSyncConfig, FileUploader, toastr, hanCrypto, $http) {
        $scope.skin = InterService.skin;

        $scope.InterService = InterService;
        $scope.aps = InterService.getCanConfigAps();
        //var url_pro = "http://";
        var url_pro = InterService.getProtocol()+"://";
        //var url_port= ":8080";
        var url_port= ":"+InterService.getPort();

        $scope.userNameInfo = window.localStorage.username;
        $scope.$watch('InterService', function(newVal, oldVal) {
            if (newVal !== oldVal) {
                $scope.aps = InterService.getCanConfigAps();
            }
        }, true);

        $scope.authenticationParams = {
            "CaptiveStatus":false,
            "CaptiveType": 0,
            "CaptiveTime":"",
        };

        $scope.Authconf={
            "type" : "account"
        };


        $scope.CurrentWLANLists = ["test", "haplet", "test2"];
        $scope.customized_portal = false;
        $scope.add_local_auth_user = false;
        $scope.add_access_code = false;
        $scope.batch_import = false;
        $scope.batch_code = false;
	    $scope.localuser_detail = false;
        $scope.edit_local_auth_user = false;
        $scope.modifybefore = {};
        $scope.isGetTime = true;

        $scope.localUserList = [];
        $scope.localUserListTemp = {
            "UserName":"",
            "Password": "",
            "PasswordConfirm":"",
            "FirstName ":"",
            "LastName":"",
            "Mail":"",
            "Phone":"",
            "Company": "",
            "StartingDate": "",
            "EndingDate": ""
        };

        $scope.accessCodeList = [];
        $scope.accessCodeTemp = {
            access_code: ""
        };

        $scope.tftpInfo = {
            "FTFPStatus":"",
            "TFTPIp": "",
            "TFTPCycle":"",
            "TFTPIpManu":""
        };

        $scope.tftpCycle = [
            { name: "1h", value: "1"},
            { name: "2h", value: "2"},
            { name: "4h", value: "4"}];

        $scope.cycleLevel = $scope.tftpCycle[0];

        $scope.echoCycleLevels = function(level) {
            if(1 == level){
                $scope.cycleLevel = $scope.tftpCycle[0];
            }else if(2 == level){
                $scope.cycleLevel = $scope.tftpCycle[1];
            }else if(4 == level){
                $scope.cycleLevel = $scope.tftpCycle[2];
            }
        };
        /*captive portal switch and auth type*/
        $scope.getcaptiveportalinfo = function(){
            authentifiedRequest.get("/getauthswitch", null, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.authenticationParams = data.result;
                    $scope.isGetTime = false;
                    if(0 == $scope.authenticationParams.CaptiveType){
                        $scope.Authconf.type = "account";
                    }else if(1 == $scope.authenticationParams.CaptiveType) {
                        $scope.Authconf.type = "accesscode";
                    }else if(2 == $scope.authenticationParams.CaptiveType){
                        $scope.Authconf.type = "terms";
                    }
                }
            },function(){
            })
        };

        $scope.setPortalSwitch = function(){
           /* var operatorMsg = 'Set captive portal switch';*/
            var operatorMsg = "access_captiveportal_switch";
            var requestParas = JSON.stringify($scope.authenticationParams.CaptiveStatus);
            batchSyncConfig.request("put", "/setportalswitch", null, requestParas, function(){
                $scope.getcaptiveportalinfo();
            },null, operatorMsg);
        };

        $scope.setPortalType = function(type){
           /* var operatorMsg = 'Set captive portal auth type';*/
            var operatorMsg =  "access_captiveportal_type";
            var requestParas = JSON.stringify(type);
            batchSyncConfig.request("put", "/setportaltype", null, requestParas, function(){
                $scope.getcaptiveportalinfo();
            },null, operatorMsg);
        };

        /*user*/
        $scope.getLocalUser = function (){
            var params = {};
            authentifiedRequest.get("/userlist", params, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.localUserList = data.result;
			if(null != $scope.localUserList){
				for(var i = 0; i < $scope.localUserList.length; i++){
					$scope.localUserList[i].Password = hanCrypto.decoder($scope.localUserList[i].Password);
				}
			}
                }
            },function(){
            })
        };

        $scope.userFilterDuplicateObject = function(array, acltemp) {
            var temp = false;
            var tempobj = acltemp;

            //compare key and value
            $.each(array,function(i,val){
                if((val.UserName == tempobj.UserName)){
                    temp = true;
                    return false;
                }
            });
            
            return temp;
        }

        $scope.Add_Localauth_User = function(localUserTemp){

            var start_date = $("#add_start_date_value").val();
            var end_date = $("#add_end_date_value").val();
            var localUserInfo = {};
            $scope.localUserListTemp.StartingDate = start_date;
            $scope.localUserListTemp.EndingDate = end_date;

            if($scope.localUserListTemp.FirstName == null){
                $scope.localUserListTemp.FirstName = "#";
            }else {
                if(($scope.localUserListTemp.FirstName).indexOf(" ")>0){
                    $scope.localUserListTemp.FirstName = ($scope.localUserListTemp.FirstName).replace(/ /g,"?");
                }
            }

            if($scope.localUserListTemp.LastName == null){
                $scope.localUserListTemp.LastName = "#";
            }else {
                if(($scope.localUserListTemp.LastName).indexOf(" ")>0){
                    $scope.localUserListTemp.LastName = ($scope.localUserListTemp.LastName).replace(/ /g,"?");
                }
            }

            if($scope.localUserListTemp.Company == null){
                $scope.localUserListTemp.Company = "#";
            }else {
                if(($scope.localUserListTemp.Company).indexOf(" ")>0){
                    $scope.localUserListTemp.Company = ($scope.localUserListTemp.Company).replace(/ /g,"?");
                }
            }


            angular.copy(localUserTemp, localUserInfo);
            /*var operatorMsg = 'Add local auth user';*/
            var operatorMsg = 'access_addauthuser_2';
            if(null != $scope.localUserList){
                var index = $scope.userFilterDuplicateObject($scope.localUserList, localUserInfo);
                if(true == index){
                   /* toastr.info('The username already add!', '');*/
                    toastr.info($translate.instant("access_addauthuser_1"), '');
                    return ;
                }
                if(localUserInfo.StartingDate == "" || localUserInfo.EndingDate == ""){
                    toastr.info($translate.instant("access_addauthuser_5"), '');
                    return ;
                }
                if(($scope.authenticationParams.CaptiveTime > localUserInfo.StartingDate) && 
                    (localUserInfo.StartingDate > localUserInfo.EndingDate)){
                    toastr.info($translate.instant("access_addauthuser_5"), '');
                    return ;
                }
            }
            localUserInfo.Password = hanCrypto.encoder(localUserInfo.Password);
            var requestParas = JSON.stringify(localUserInfo);
            batchSyncConfig.request("put", "/adduser", null, requestParas, function(){
                $scope.getLocalUser();
            },null, operatorMsg);
            $("form[name='add_localauth_user']")[0].reset();
            $scope.Cancel();
        };

        $scope.Edit_localauth_user = function(modifyafter){
            var start_date = $("#edit_start_value").val();
            var end_date = $("#edit_end_value").val();
            var operatorMsg = $translate.instant("authModifyLocalUser");
            var modifyuser = [];
            var modifybefore = $scope.modifybefore;

            if($scope.localUserListTemp.FirstName == null){
                $scope.localUserListTemp.FirstName = "#";
            }else {
                if(($scope.localUserListTemp.FirstName).indexOf(" ")>0){
                    $scope.localUserListTemp.FirstName = ($scope.localUserListTemp.FirstName).replace(/ /g,"?");
                }
            }
            if($scope.localUserListTemp.LastName == null){
                $scope.localUserListTemp.LastName = "#";
            }else {
                if(($scope.localUserListTemp.LastName).indexOf(" ")>0){
                    $scope.localUserListTemp.LastName = ($scope.localUserListTemp.LastName).replace(/ /g,"?");
                }
            }
            if($scope.localUserListTemp.Company == null){
                $scope.localUserListTemp.Company = "#";
            }else {
                if(($scope.localUserListTemp.Company).indexOf(" ")>0){
                    $scope.localUserListTemp.Company = ($scope.localUserListTemp.Company).replace(/ /g,"?");
                }
            }

            //$scope.localUserListTemp.StartingDate = start_date;
            modifyafter.StartingDate = start_date;
            //$scope.localUserListTemp.EndingDate = end_date;
            modifyafter.EndingDate = end_date;

            if(modifyafter.StartingDate == "" || modifyafter.EndingDate == ""){
                toastr.info($translate.instant("access_addauthuser_5"), '');
                return ;
            }

            if(($scope.authenticationParams.CaptiveTime > modifyafter.StartingDate) && 
                (modifyafter.StartingDate > modifyafter.EndingDate)){
                toastr.info($translate.instant("access_addauthuser_5"), '');
                return ;
            }
             
            modifybefore.Password = hanCrypto.encoder(modifybefore.Password);
            modifyafter.Password = hanCrypto.encoder(modifyafter.Password);
            modifyuser.push(modifybefore);
            modifyuser.push(modifyafter);
            var requestParas = JSON.stringify(modifyuser);
            batchSyncConfig.request("put", "/modifyuser", null, requestParas, function(){
                $scope.getLocalUser();
            },null,operatorMsg);
            $("form[name='edit_localauth_user']")[0].reset();
            $scope.Cancel();
        };


        //import user
        $scope.usernum = 0;
        var user = $scope.user = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });

        $scope.clearuser = function(){
            user.clearQueue();
        }

        user.onAfterAddingFile = function(fileItem) {
            var regex = /[\S|\s]+.csv$/;
            var result=regex.test((fileItem.file.name).toLowerCase());
            if(!result){
                $scope.clearuser();
                /*toastr.info('The file format is not csv!', '');*/
                toastr.info($translate.instant("access_file_format_csv"), '');
            }
        }

        user.onCompleteItem = function(item, response, status, headers){
        $scope.usernum++;
             if($scope.usernum < $scope.aps.length){
                $scope.importuser(user.queue[0]);
             }else{
                $scope.usernum=0;
                $scope.getLocalUser();
                var confirm_tip = $translate.instant("access_addauthuser_3") + response.total + " " + $translate.instant("access_addauthuser_4") + response.successTotal +"!";
                toastr.info(confirm_tip, '');
                //toastr.info($translate.instant("access_addauthuser_3"+response.result, '');
             }
        };
        $scope.importuser = function(item) {
            if(null != $scope.aps){
                 $scope.filename = item;
                 user.queue[0].url=url_pro+$scope.aps[$scope.usernum].ip+url_port+"/importuser/"+item.file.name;
                 user.queue[0].upload();
            }
        }

        $scope.downloadcsv = function(x){
            /*var operatorMsg = "Download configration of ap";*/
            var operatorMsg = $translate.instant("downAccountFile");
            var loginfo = [{
                'ip':$scope.aps[0].ip,
                'success':false,
                'msg':''}];
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("access_download_account_file"),
                callback: function(result) {
                    if(result){
                        $http({
                            method: 'get',
                            url: "/downloadcsv",
                            headers: {
                                'Authorization': 'sessionName ' + window.localStorage.sessionId
                            }
                        }).success( function(data, status, headers) {
                            var octetStreamMime = 'application/octet-stream';
                            var success = false;
                            headers = headers();
                            var filename_str = headers['content-disposition'];
                            var strs= new Array();
                            strs=filename_str.split("=");
                            var filename=strs[1];
                            var contentType = headers['content-type'] || octetStreamMime;
                            try
                            {
                                //console.log("Trying saveBlob method ...");
                                var blob = new Blob([data], { type: contentType });
                                if(navigator.msSaveBlob) {
                                    navigator.msSaveBlob(blob, filename);
                                }
                                else {
                                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
                                    if(saveBlob === undefined) throw "Not supported";
                                    else{
                                        saveBlob(blob, filename);
                                    }
                                    //console.log("saveBlob succeeded");
                                    success = true;
                                }
                            }catch(ex) {
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
                                        }catch(ex) {
                                            //console.log("Download link method with window.location failed with the following exception:");
                                            //console.log(ex);
                                        }
                                    }
                                }
                            }
                            if(!success)
                            {
                                //console.log("No methods worked for saving the arraybuffer, using last resort window.open");
                                window.open(httpPath, '_blank', '');
                            }
                        })
                            .error(function(data, status) {
                                //console.log("Request failed with status: " + status);
                                loginfo[0].success = false;
                                loginfo[0].msg = $translate.instant("failedServer");
                                operationLog.setLog(operatorMsg, loginfo);
                                toastr.warning($translate.instant("access_communicate_error"));
                            });

                    }
                }
            });
            //bootbox.confirm($translate.instant("access_download_account_file"), function(result) {
            //    if(result){
            //        $http({
            //            method: 'get',
            //            url: "/downloadcsv",
            //            headers: {
            //                'Authorization': 'sessionName ' + window.localStorage.sessionId
            //            }
            //        }).success( function(data, status, headers) {
            //            var octetStreamMime = 'application/octet-stream';
            //            var success = false;
            //            headers = headers();
            //            var filename_str = headers['content-disposition'];
            //            var strs= new Array();
            //            strs=filename_str.split("=");
            //            var filename=strs[1];
            //            var contentType = headers['content-type'] || octetStreamMime;
            //            try
            //            {
            //                //console.log("Trying saveBlob method ...");
            //                var blob = new Blob([data], { type: contentType });
            //                if(navigator.msSaveBlob) {
            //                    navigator.msSaveBlob(blob, filename);
            //                }
            //                else {
            //                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
            //                    if(saveBlob === undefined) throw "Not supported";
            //                    else{
            //                        saveBlob(blob, filename);
            //                    }
            //                    //console.log("saveBlob succeeded");
            //                    success = true;
            //                }
            //            }catch(ex) {
            //                //console.log("saveBlob method failed with the following exception:");
            //                //console.log(ex);
            //            }
            //            if(!success){
            //                var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
            //                if(urlCreator){
            //                    var link = document.createElement('a');
            //                    if('download' in link){
            //                        try {
            //                            //console.log("Trying download link method with simulated click ...");
            //                            var blob = new Blob([data], { type: contentType });
            //                            var url = urlCreator.createObjectURL(blob);
            //                            link.setAttribute('href', url);
            //                            link.setAttribute("download", filename);
            //                            var event = document.createEvent('MouseEvents');
            //                            event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
            //                            link.dispatchEvent(event);
            //                            //console.log("Download link method with simulated click succeeded");
            //                            success = true;
            //                        } catch(ex) {
            //                            //console.log("Download link method with simulated click failed with the following exception:");
            //                            //console.log(ex);
            //                        }
            //                    }
            //                    if(!success){
            //                        try{
            //                            //console.log("Trying download link method with window.location ...");
            //                            var blob = new Blob([data], { type: octetStreamMime });
            //                            var url = urlCreator.createObjectURL(blob);
            //                            window.location = url;
            //                            //console.log("Download link method with window.location succeeded");
            //                            success = true;
            //                        }catch(ex) {
            //                            //console.log("Download link method with window.location failed with the following exception:");
            //                            //console.log(ex);
            //                        }
            //                    }
            //                }
            //            }
            //            if(!success)
            //            {
            //                //console.log("No methods worked for saving the arraybuffer, using last resort window.open");
            //                window.open(httpPath, '_blank', '');
            //            }
            //        })
            //            .error(function(data, status) {
            //                //console.log("Request failed with status: " + status);
            //                loginfo[0].success = false;
            //                loginfo[0].msg = $translate.instant("failedServer");
            //                operationLog.setLog(operatorMsg, loginfo);
            //                toastr.warning($translate.instant("access_communicate_error"));
            //            });
            //
            //    }
            //});
        };

        $scope.Delete_LocalUser = function(selectUser){
            // var requestParas = JSON.stringify(selectUser);
            var operatorMsg = 'access_delauthuser_1';
            var confirm_tip = $translate.instant("access_delauthuser_2") + selectUser.UserName + "?";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: confirm_tip,
                callback: function(result) {
                    if(result){
                        selectUser.Password = hanCrypto.encoder(selectUser.Password);
                        var requestParas = selectUser;
                        batchSyncConfig.request("put", "/deleteuser", null, requestParas, function(){
                            $scope.getLocalUser();
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        selectUser.Password = hanCrypto.encoder(selectUser.Password);
            //        var requestParas = selectUser;
            //        batchSyncConfig.request("put", "/deleteuser", null, requestParas, function(){
            //            $scope.getLocalUser();
            //        },null, operatorMsg);
            //    }
            //});
        };

        /*
        *get and set access code 
        */
        $scope.getAccessCode = function(){
            var params = {};
            authentifiedRequest.get("/getaccesscode", params, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.accessCodeList = data.result;
					if(null != $scope.accessCodeList){
						for(var i = 0; i < $scope.accessCodeList.length; i++){
							$scope.accessCodeList[i].access_code = hanCrypto.decoder($scope.accessCodeList[i].access_code);
						}
					}
                }
            },function(){
            })
        };

        $scope.codeFilterDuplicateObject = function(array, acltemp) {
            var temp = -1;
            var tempobj = acltemp;

            //compare key and value
            $.each(array,function(i,val){
                if((val.access_code == tempobj.access_code)){
                    temp = 0;
                    return temp;
                }
            });
            
            return temp;
        }

	   $scope.Add_AccessCode = function(){
            var operatorMsg = 'access_add_accesscode_1';
            $scope.accessCodeInfo = {};
           angular.copy($scope.accessCodeTemp, $scope.accessCodeInfo);

            if(0 != $scope.accessCodeList.length){
                var index = $scope.codeFilterDuplicateObject($scope.accessCodeList, $scope.accessCodeInfo);
                if(0 == index){
                    toastr.info($translate.instant("access_add_accesscode_2"), '');
                    return ;
                }
            }
            $scope.accessCodeInfo.access_code = hanCrypto.encoder($scope.accessCodeInfo.access_code);
            var requestParas = JSON.stringify($scope.accessCodeInfo.access_code);
            batchSyncConfig.request("put", "/addaccesscode", null, requestParas, function(){
                $scope.getAccessCode();
            },null, operatorMsg);

            $scope.Cancel();
        };

        //import code
        $scope.codenum = 0;
        var code = $scope.code = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });

        $scope.clearcode = function(){
            code.clearQueue();
        }

        code.onAfterAddingFile = function(fileItem) {
            var regex = /[\S|\s]+.csv$/;
            var result=regex.test((fileItem.file.name).toLowerCase());
            if(!result){
                $scope.clearcode();
                /*toastr.info('The file format is not csv!', '');*/
                toastr.info($translate.instant("access_file_format_csv"), '');
            }
        }

        code.onCompleteItem = function(item, response, status, headers) {
        $scope.codenum++;
             if($scope.codenum < $scope.aps.length){
                $scope.importcode(code.queue[0]);
             }else{
                $scope.codenum=0;
                $scope.getAccessCode();
                var confirm_tip = $translate.instant("access_addauthuser_3") + response.total +" " + $translate.instant("access_addauthuser_4") + response.successTotal +"!";
                toastr.info(confirm_tip, '');
             }
        };
        $scope.importcode = function(item) {
            if(null != $scope.aps){
                 $scope.filename = item;
                 code.queue[0].url=url_pro+$scope.aps[$scope.codenum].ip+url_port+"/importcode/"+item.file.name;
                 code.queue[0].upload();
            }
        }

        $scope.downloadcodecsv = function(x){
           /* var operatorMsg = "Download configration of ap";*/
            var operatorMsg = $translate.instant("downAccessCodeFile");
            var loginfo = [{
                'ip':$scope.aps[0].ip,
                'success':false,
                'msg':''}];
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("downAccessCodeFile_2"),
                callback: function(result) {
                    if(result){
                        $http({
                            method: 'get',
                            url: "/downloadcodecsv",
                            headers: {
                                'Authorization': 'sessionName ' + window.localStorage.sessionId
                            }
                        }).success( function(data, status, headers) {
                            var octetStreamMime = 'application/octet-stream';
                            var success = false;
                            headers = headers();
                            var filename_str = headers['content-disposition'];
                            var strs= new Array();
                            strs=filename_str.split("=");
                            var filename=strs[1];
                            var contentType = headers['content-type'] || octetStreamMime;
                            try
                            {
                                console.log($translate.instant("trySaveBlob"));
                                var blob = new Blob([data], { type: contentType });
                                if(navigator.msSaveBlob) {
                                    navigator.msSaveBlob(blob, filename);
                                }
                                else {
                                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
                                    if(saveBlob === undefined) throw $translate.instant("notSupport");
                                    else{
                                        saveBlob(blob, filename);
                                    }
                                    console.log($translate.instant("saveBlobSucceed"));
                                    success = true;
                                }
                            }catch(ex) {
                                console.log($translate.instant("saveBlobFail"));
                                console.log(ex);
                            }
                            if(!success){
                                var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
                                if(urlCreator){
                                    var link = document.createElement('a');
                                    if('download' in link){
                                        try {
                                            console.log($translate.instant("tryDownLink"));
                                            var blob = new Blob([data], { type: contentType });
                                            var url = urlCreator.createObjectURL(blob);
                                            link.setAttribute('href', url);
                                            link.setAttribute("download", filename);
                                            var event = document.createEvent('MouseEvents');
                                            event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
                                            link.dispatchEvent(event);
                                            console.log($translate.instant("downloadLinkMethod"));
                                            success = true;
                                        } catch(ex) {
                                            console.log($translate.instant("downloadLinkMethodWith"));
                                            console.log(ex);
                                        }
                                    }
                                    if(!success){
                                        try{
                                            console.log($translate.instant("tryDownloadWindow"));
                                            var blob = new Blob([data], { type: octetStreamMime });
                                            var url = urlCreator.createObjectURL(blob);
                                            window.location = url;
                                            console.log($translate.instant("downloadLinkMethodWindow"));
                                            success = true;
                                        }catch(ex) {
                                            console.log($translate.instant("downloadLinkMethodWindowFail"));
                                            console.log(ex);
                                        }
                                    }
                                }
                            }
                            if(!success)
                            {
                                console.log($translate.instant("noMethodWorked"));
                                window.open(httpPath, '_blank', '');
                            }
                        })
                            .error(function(data, status) {
                                console.log($translate.instant("requestFailed") + status);
                                loginfo[0].success = false;
                                loginfo[0].msg = $translate.instant("failedServer");
                                operationLog.setLog(operatorMsg, loginfo);
                                toastr.warning($translate.instant("failedServer"));
                            });

                    }
                }
            });
            //bootbox.confirm($translate.instant("downAccessCodeFile_2"), function(result) {
            //    if(result){
            //        $http({
            //            method: 'get',
            //            url: "/downloadcodecsv",
            //            headers: {
            //                'Authorization': 'sessionName ' + window.localStorage.sessionId
            //            }
            //        }).success( function(data, status, headers) {
            //            var octetStreamMime = 'application/octet-stream';
            //            var success = false;
            //            headers = headers();
            //            var filename_str = headers['content-disposition'];
            //            var strs= new Array();
            //            strs=filename_str.split("=");
            //            var filename=strs[1];
            //            var contentType = headers['content-type'] || octetStreamMime;
            //            try
            //            {
            //                console.log($translate.instant("trySaveBlob"));
            //                var blob = new Blob([data], { type: contentType });
            //                if(navigator.msSaveBlob) {
            //                    navigator.msSaveBlob(blob, filename);
            //                }
            //                else {
            //                    var saveBlob = navigator.webkitSaveBlob || navigator.mozSaveBlob || navigator.saveBlob;
            //                    if(saveBlob === undefined) throw $translate.instant("notSupport");
            //                    else{
            //                        saveBlob(blob, filename);
            //                    }
            //                    console.log($translate.instant("saveBlobSucceed"));
            //                    success = true;
            //                }
            //            }catch(ex) {
            //                console.log($translate.instant("saveBlobFail"));
            //                console.log(ex);
            //            }
            //            if(!success){
            //                var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
            //                if(urlCreator){
            //                    var link = document.createElement('a');
            //                    if('download' in link){
            //                        try {
            //                            console.log($translate.instant("tryDownLink"));
            //                            var blob = new Blob([data], { type: contentType });
            //                            var url = urlCreator.createObjectURL(blob);
            //                            link.setAttribute('href', url);
            //                            link.setAttribute("download", filename);
            //                            var event = document.createEvent('MouseEvents');
            //                            event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
            //                            link.dispatchEvent(event);
            //                            console.log($translate.instant("downloadLinkMethod"));
            //                            success = true;
            //                        } catch(ex) {
            //                            console.log($translate.instant("downloadLinkMethodWith"));
            //                            console.log(ex);
            //                        }
            //                    }
            //                    if(!success){
            //                        try{
            //                            console.log($translate.instant("tryDownloadWindow"));
            //                            var blob = new Blob([data], { type: octetStreamMime });
            //                            var url = urlCreator.createObjectURL(blob);
            //                            window.location = url;
            //                            console.log($translate.instant("downloadLinkMethodWindow"));
            //                            success = true;
            //                        }catch(ex) {
            //                            console.log($translate.instant("downloadLinkMethodWindowFail"));
            //                            console.log(ex);
            //                        }
            //                    }
            //                }
            //            }
            //            if(!success)
            //            {
            //                console.log($translate.instant("noMethodWorked"));
            //                window.open(httpPath, '_blank', '');
            //            }
            //        })
            //            .error(function(data, status) {
            //                console.log($translate.instant("requestFailed") + status);
            //                loginfo[0].success = false;
            //                loginfo[0].msg = $translate.instant("failedServer");
            //                operationLog.setLog(operatorMsg, loginfo);
            //                toastr.warning($translate.instant("failedServer"));
            //            });
            //
            //    }
            //});
        };

        $scope.DelAccessCode = function(access_code){
            var operatorMsg = 'access_del_accesscode_1';
            var confirm_tip = $translate.instant("access_del_accesscode_2") + access_code + "?";
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: confirm_tip,
                callback: function(result) {
                    if(result){
                        access_code = hanCrypto.encoder(access_code);
                        batchSyncConfig.request("delete", "/deleteaccesscode/" + access_code, null, null, function(){
                            $scope.getAccessCode();
                            //clear temp display
                            $scope.accessCodeTemp = {access_code: ""};
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm(confirm_tip, function(result){
            //    if(result){
            //        access_code = hanCrypto.encoder(access_code);
            //        batchSyncConfig.request("delete", "/deleteaccesscode/" + access_code, null, null, function(){
            //            $scope.getAccessCode();
            //            //clear temp display
            //            $scope.accessCodeTemp = {access_code: ""};
            //        },null, operatorMsg);
            //    }
            //});
        };

        $scope.restoredefault = function(){
            bootbox.confirm({
                buttons: {
                    cancel: {
                        label: $translate.instant("Cancel")
                    },
                    confirm: {
                        label: $translate.instant("OK")
                    }
                },
                message: $translate.instant("access_restore_portal_1"),
                callback: function(result) {
                    if(result) {
                        /*var operatorMsg = 'restore default portal logo, background image and agreement terms';*/
                        var operatorMsg = 'access_restore_portal_2';
                        batchSyncConfig.request("put", "/restoredefault", null, null, function(){
                        },null, operatorMsg);
                    }
                }
            });
            //bootbox.confirm($translate.instant("access_restore_portal_1"), function(result) {
            //    if(result) {
            //        /*var operatorMsg = 'restore default portal logo, background image and agreement terms';*/
            //        var operatorMsg = 'access_restore_portal_2';
            //        batchSyncConfig.request("put", "/restoredefault", null, null, function(){
            //        },null, operatorMsg);
            //    }
            //});
        };

		//upload logo
        $scope.filename={};
        $scope.logonum=0;
        $scope.bgnum=0;
        $scope.licnum=0;
        var logo = $scope.logo = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });

        $scope.clearlogo = function(){
            logo.clearQueue();
        }

        logo.onAfterAddingFile = function(fileItem) {
            var regex = /[\S|\s]+.(png|jpg)/;
            var result=regex.test((fileItem.file.name).toLowerCase());
            if(!result){
                $scope.clearlogo();
                /*toastr.info('The file format is not png!', '');*/
                toastr.info($translate.instant("access_file_format_png"), '');
            }
            var size = fileItem.file.size/1024;
            if(size>20){
                $scope.clearlogo();
                toastr.warning($translate.instant("access_logo_toobig"), '');
                return;
            }
        };

        logo.onCompleteAll = function() {
        $scope.logonum++;
            if($scope.logonum < $scope.aps.length){
                $scope.uploadlogo(logo.queue[0]);
            }else{
                $scope.logonum=0;
            }
        };
        $scope.uploadlogo = function(item) {
            if(null != $scope.aps){
                 $scope.filename = item;
                 logo.queue[0].url=url_pro+$scope.aps[$scope.logonum].ip+url_port+"/uploadlogo/"+item.file.name;
                 logo.queue[0].upload();
            }
        }

	    //upload main

		var main = $scope.main = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });

        $scope.clearmain = function(){
            main.clearQueue();
        }

        main.onAfterAddingFile = function(fileItem) {
            var regex = /[\S|\s]+.(png|jpg)$/;
            var result=regex.test((fileItem.file.name).toLowerCase());
            if(!result){
                $scope.clearmain();
                /*toastr.info('The file format is not png!', '');*/
                toastr.info($translate.instant("access_file_format_png"), '');
            }
            var size = fileItem.file.size/1024;
            if(size > 200){
                 $scope.clearmain();
                toastr.warning($translate.instant("access_background_toobig"), '');
                return;
            }
        }
        main.onCompleteAll = function() {
        $scope.bgnum++;
             if($scope.bgnum < $scope.aps.length){
                $scope.uploadmain(main.queue[0]);
             }else{
                $scope.bgnum=0;
             }
        };
        $scope.uploadmain = function(item) {
            if(null != $scope.aps){
                 $scope.filename = item;
                 main.queue[0].url=url_pro+$scope.aps[$scope.bgnum].ip+url_port+"/uploadmain/"+item.file.name;
                 main.queue[0].upload();
            }
        }

		//upload license
		var license = $scope.license = new FileUploader({
            removeAfterUpload: false,
            headers: {
                'Authorization': 'sessionName ' + window.localStorage.sessionId
            }
        });

        $scope.clearlicense = function(){
            license.clearQueue();
        }

        license.onAfterAddingFile = function(fileItem) {
            var regex = /[\S|\s]+.txt$/;
            var result=regex.test(fileItem.file.name);
            if(!result){
                $scope.clearlicense();
                toastr.info($translate.instant("access_file_format_txt"), '');
            }
            var size = fileItem.file.size/1024;
            if(size > 50){
                $scope.clearlicense();
                toastr.warning($translate.instant("access_term_toobig"), '');
                return;
            }
        };

        license.onCompleteAll = function() {
        $scope.licnum++;
             if($scope.licnum < $scope.aps.length){
                $scope.uploadlicense(license.queue[0]);
             }else{
                $scope.licnum=0;
             }
        };

        $scope.uploadlicense = function(item) {
            if(null != $scope.aps){
                 $scope.filename = item;
                 license.queue[0].url=url_pro+$scope.aps[$scope.licnum].ip+url_port+"/uploadlicense/"+item.file.name;
                 license.queue[0].upload();
            }
        }
		

        $scope.Cancel= function(){
            $scope.customized_portal = false;
            $scope.add_local_auth_user = false;
            $scope.localuser_detail = false;
            $scope.edit_local_auth_user = false;
	    $scope.localuser_detail = false;
            $scope.add_access_code = false;
            $scope.batch_import = false;
            $scope.batch_code = false;
        };
        $scope.ShowAddLocalUser = function(){
            $scope.Cancel();
            $scope.localUserListTemp = {};
            $("form[name='add_localauth_user']")[0].reset();
            this.add_localauth_user.$setPristine();
            $scope.add_local_auth_user = true;

            var APTime = $scope.authenticationParams.CaptiveTime;
            APTime = APTime.replace(/\./g, "/");

            var min_date = APTime;

            $("#add_startdatepicker").datetimepicker({
                format: 'YYYY.MM.DD',
                useCurrent:false,
                ignoreReadonly:true,
                minDate: min_date
            }).on("dp.change", function (e) {
                $('#add_enddatepicker').data("DateTimePicker").minDate(e.date);
                //$scope.localUserListTemp.StartingDate = e.date.format("YYYY.MM.DD");
            });
            $("#add_enddatepicker").datetimepicker({
                format: 'YYYY.MM.DD',
                useCurrent:false,
                ignoreReadonly:true,
                minDate: min_date
            }).on("dp.change", function (e) {
                $('#add_startdatepicker').data("DateTimePicker").maxDate(e.date);
                //$scope.localUserListTemp.StartingDate = e.date.format("YYYY.MM.DD");
            });
        };
        $scope.ShowLocalUserDetail = function(selectUser){
            $scope.Cancel();
            $scope.localuser_detail = true;
            $scope.localUserListTemp = angular.copy(selectUser);
            if($scope.localUserListTemp.FirstName == "#"){
                $scope.localUserListTemp.FirstName = null;
            }else{
                if(($scope.localUserListTemp.FirstName).indexOf("?")>0){
                    $scope.localUserListTemp.FirstName = ($scope.localUserListTemp.FirstName).replace(/\?/g," ");
                }
            }
            if($scope.localUserListTemp.LastName == "#"){
                $scope.localUserListTemp.LastName = null;
            }else{
                if(($scope.localUserListTemp.LastName).indexOf("?")>0){
                    $scope.localUserListTemp.LastName = ($scope.localUserListTemp.LastName).replace(/\?/g," ");
                }
            }
            if($scope.localUserListTemp.Company == "#"){
                $scope.localUserListTemp.Company = null;
            }else{
                if(($scope.localUserListTemp.Company).indexOf("?")>0){
                    $scope.localUserListTemp.Company = ($scope.localUserListTemp.Company).replace(/\?/g," ");
                }

            }

            //angular.copy(selectUser, $scope.localUserListTemp);
        };

        $scope.Show_Edit_Localauth_User = function(selectUser){

            var APTime;
            var end_min_date;
            var start_date;
            var start_min_date;
            $scope.localUserListTemp = angular.copy(selectUser);
            if($scope.localUserListTemp.FirstName == "#"){
                $scope.localUserListTemp.FirstName = null;
            }else {
                if(($scope.localUserListTemp.FirstName).indexOf("?")>0){
                    $scope.localUserListTemp.FirstName = ($scope.localUserListTemp.FirstName).replace(/\?/g," ");
                }
            }
            if($scope.localUserListTemp.LastName == "#"){
                $scope.localUserListTemp.LastName = null;
            }else {
                if(($scope.localUserListTemp.LastName).indexOf("?")>0){
                    $scope.localUserListTemp.LastName = ($scope.localUserListTemp.LastName).replace(/\?/g," ");
                }

            }
            if($scope.localUserListTemp.Company == "#"){
                $scope.localUserListTemp.Company = null;
            }else{
                if(($scope.localUserListTemp.Company).indexOf("?")>0){
                    $scope.localUserListTemp.Company = ($scope.localUserListTemp.Company).replace(/\?/g," ");
                }
            }



            APTime = $scope.authenticationParams.CaptiveTime;
            end_min_date = APTime.replace(/\./g, "/");

            start_date = selectUser.StartingDate;
            start_date = start_date.replace(/\./g, "/");
            if(start_date < end_min_date){
                start_min_date = start_date;
            }else{
                start_min_date = end_min_date;
            }
           
            $("#edit_start_date").datetimepicker({
                format: 'YYYY.MM.DD', 
                useCurrent:false,
                ignoreReadonly:true,
                minDate: start_min_date
            }).on("dp.change", function (e) {
                var current_value = $("#edit_start_value").val();
                var time_tmp = current_value.replace(/\./g, "/");
                if(time_tmp>end_min_date){
                    $('#edit_end_date').data("DateTimePicker").minDate(e.date);
                }else{
                    $('#edit_end_date').data("DateTimePicker").minDate(end_min_date);
                }
                
            });
            $('#edit_start_date').data("DateTimePicker").minDate(start_min_date);


            $("#edit_end_date").datetimepicker({
                format: 'YYYY.MM.DD',
                useCurrent:false,
                ignoreReadonly:true,
                minDate:end_min_date
            }).on("dp.change", function (e) {
                $('#edit_start_date').data("DateTimePicker").maxDate(e.date);
            });
            $scope.Cancel();
            $scope.edit_local_auth_user = true;
            $scope.localuser_param_error = false;
            $scope.mailError = false;
            angular.copy(selectUser, $scope.modifybefore);
            //angular.copy(selectUser, $scope.localUserListTemp);
            $scope.localUserListTemp.PasswordConfirm = $scope.localUserListTemp.Password;
            $('#edit_start_date').data("DateTimePicker").date($scope.localUserListTemp.StartingDate); 
            $('#edit_end_date').data("DateTimePicker").date($scope.localUserListTemp.EndingDate);

        };

        $scope.ShowCustomizedPortal = function(){
            $scope.Cancel();
            $scope.customized_portal = true;
        };
        $scope.ShowAddWhite = function(){
            $("form[name='add_whitelist']")[0].reset();
            $scope.customized_portal = false;
            $scope.add_local_auth_user = false;
            $scope.add_access_code = false;
            $scope.batch_import = false;
            $scope.batch_code = false;
	    $scope.localuser_detail = false;
        };
        $scope.ShowAddMACAccount = function(){
            $("form[name='add_local_mac']")[0].reset();
            $scope.customized_portal = false;
            $scope.add_local_auth_user = false;
            $scope.add_access_code = false;
            $scope.batch_import = false;
            $scope.batch_code = false;
	     $scope.localuser_detail = false;
        };
        $scope.ShowAddAccessCode = function(){
            $scope.Cancel();
            $scope.add_access_code = true;
        };
        $scope.ShowBatchImport = function(){
            $scope.Cancel();
            $scope.batch_import = true;
            $scope.batch_code = false;
        };
        $scope.ShowCodeImport = function(){
            $scope.customized_portal = false;
            $scope.add_local_auth_user = false;
            $scope.add_access_code = false;
            $scope.batch_import = false;
            $scope.batch_code = true;
        }; 

        /* TFTP server */
        $scope.getTftpInfo = function(){
            authentifiedRequest.get("/getTftpInfo", null, function(data, status){
                if(status == 200 && data != null && data.success){
                    $scope.tftpInfo = data.result;
                    $scope.echoCycleLevels($scope.tftpInfo.TFTPCycle);
                }
            },function(){
            })
        };

        $scope.setTftpSwitch = function(){
            /*var operatorMsg = 'Set TFTP switch';*/
            var operatorMsg = 'access_tftp_switch';
            var requestParas = JSON.stringify($scope.tftpInfo.FTFPStatus);
            batchSyncConfig.request("put", "/settftpswitch", null, requestParas, function(){

            },null, operatorMsg);
        };
    
        $scope.changeCycleLevel = function () {
            if(this.cycleLevel.value =="1"){
                $scope.tftpInfo.TFTPCycle = "1";
            }else if(this.cycleLevel.value =="2"){
                $scope.tftpInfo.TFTPCycle = "2";
            }else if(this.cycleLevel.value =="4"){
                $scope.tftpInfo.TFTPCycle = "4";
            }
        }

        $scope.saveTftpInfo = function(){
            /*var operatorMsg = 'Set tftpInfo switch';*/
            var operatorMsg = 'access_save_tftp_conf';

            //$scope.tftpInfo.TFTPCycle = this.cycleLevel.value;
            var requestParas = JSON.stringify($scope.tftpInfo);
            batchSyncConfig.request("put", "/savetftpinfo", null, requestParas, function(){

            },null, operatorMsg);
        };

        $scope.uploadTftpNow = function(){
            /*var operatorMsg = 'TFTP upload now';*/
            var operatorMsg = 'access_tftp_upload_now';
            $scope.tftpInfoTemp = $scope.tftpInfo;
            $scope.tftpInfoTemp.TFTPCycle = 0;
            var requestParas = JSON.stringify($scope.tftpInfoTemp);
            batchSyncConfig.request("put", "/uploadtftpinfo", null, requestParas, function(){

            },null, operatorMsg);
        };

        /**        // $scope.DeletePortalServer = function(selectServer){
        //     alert("delete portal/radius server: "+selectServer.WLAN);
        // };

         **获取当前行client详细信息
         **/
        $scope.currentLine = 0;//记录上次点击的行号
        $scope.getCurrentClientDetail = function(currentDetail){
            $scope.localUserListTemp=currentDetail;
        };

        $scope.close = function() {
            $modalInstance.close();
        };

        $scope.localuser_param_error = false;
        $scope.mailError = false;
        $scope.checkMail = function(mail){
            if(mail != null && mail != ""){
                var len = mail.length;
                if(len > 64){
                    $scope.localuser_param_error = true;
                    $scope.mailError = true;
                }
                else{
                    $scope.localuser_param_error = false;
                    $scope.mailError = false;
                }
            }
            else{
                $scope.localuser_param_error = false;
                $scope.mailError = false;
            }
        };

        $scope.getcaptiveportalinfo();
        $scope.getLocalUser();
        $scope.getAccessCode();
        $scope.getTftpInfo();


        //init config opration
        $scope.currentUser = window.localStorage.username;

        $scope.logoutToLoginPage = function(){
            authentifiedRequest.post('/authentication/logout', null, null, function(data){
                // must return
                window.location.href = "/static/login.html";
            });
        }

        //the captive portal switch and url
        $scope.portalInfo = {"switch":false,"url":""};
        var data = {enable:true,url:""};

        //get captive portal switch and url
        getCaptiveSwitch();
        getCaptiveUrl();
        function getCaptiveSwitch(){
            authentifiedRequest.get("/captive/getSwitch", null, function(response) {
                if (response != null && response.success) {
                    if(response.result == '1'){//TODO
                        $scope.portalInfo.switch = true;
                        $scope.isFormat = false;
                        $scope.checkbox_checked = false;
                        $scope.checkButton = false;

                    }else {
                        $scope.portalInfo.switch = false;
                        $scope.isFormat = true;
                        $scope.checkbox_checked = false;
                        $scope.checkButton = false;
                    }
                }
            }, function() { //error

            });

        }

        function getCaptiveUrl(){
            authentifiedRequest.get("/captive/getUrl", null, function(response) {
                if (response != null && response.success) {
                    $scope.portalInfo.url = response.result;
                }
            }, function() { //error

            });
        }

        //set captive portal switch and url
        $scope.setPortalUrlSwitch = function () {
            batchSyncConfig.request("put", "/captive/setSwitch", null, data, function(response) {
                if(response != null && response.success){

                }else{

                }
            },null,null);
        }
        $scope.setPortalUrl = function () {

            batchSyncConfig.request("put", "/captive/setUrl", null, data, function(response) {
                if(response != null && response.success){

                }else{

                }
            },null,null);
        }


        $scope.setPortalCaptive = function () {
            if($scope.portalInfo.switch){
                data.enable = $scope.portalInfo.switch;
                data.url = $scope.portalInfo.url;
            }else{
                data.enable = $scope.portalInfo.switch;
                data.url = "";
            }
            $scope.setPortalUrlSwitch();
            $scope.setPortalUrl();
        }

        $scope.configStatus = function () {
            if($scope.portalInfo.switch){//选中，可编辑
                $scope.isFormat = false;
            }else{//未选中，不可编辑
                $scope.isFormat = true;
                $scope.checkButton = false;
            }
        }
        $scope.changeFormat = function () {
            var url = $scope.portalInfo.url;
            var strRegex = "http://*";
            var re=new RegExp(strRegex);
            //re.test()
            if(re.test(url)){
                $scope.checkbox_checked = false;
                $scope.checkButton = false;
            }else{
                console.info("not fromat");
                $scope.checkbox_checked = true;
                $scope.checkButton = true;
            }
        }


    }])
;
