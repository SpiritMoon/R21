angular.module('login', ["ui.bootstrap",
        "ui.router",
        "pascalprecht.translate",
        "ngCookies",
        "toastr"
    ])
    .config(['toastrConfig', function(toastrConfig) {
        angular.extend(toastrConfig, {
            allowHtml: true,
            closeButton: true,
            closeHtml: '<button>&times;</button>',
            containerId: 'toast-container',
            extendedTimeOut: 1000,
            iconClasses: {
                error: 'toast-error',
                info: 'toast-info',
                success: 'toast-success',
                warning: 'toast-warning'
            },
            messageClass: 'toast-message',
            positionClass: 'toast-top-right',
            preventOpenDuplicates: false,
            tapToDismiss: false,
            timeOut: 6000,
            titleClass: 'toast-title',
            toastClass: 'toast'
        });
    }])
    /**config global filter,jump into login.html if returning 403 error**/
    .config(['$httpProvider', function($httpProvider) {

        $httpProvider.interceptors.push(function() {
            return {
                responseError: function(response) {
                    if (response.status == 403) {

                        window.location.href = "/static/login.html";
                    }
                    return response;
                }
            }
        });
    }])
    /** package $http£¬provide get£¬post method£¬add Authorization in header**/
    /** package $http£¬provide get£¬post method£¬add  Authorization in header**/
    .factory('authentifiedRequest', ['$http', function($http) {
        return {
            get: function(url, params, successCallback, errorCallback) {
                $http({
                    method: 'get',
                    url: url,
                    params: params,
                    timeout: 15000,
                    headers: {
                        'Authorization': 'sessionName ' + window.localStorage.sessionId
                    }
                }).success(successCallback).error(errorCallback);
            },
            put: function(url, params, data, successCallback, errorCallback) {
                $http({
                    method: 'put',
                    url: url,
                    params: params,
                    data: data,
                    timeout: 15000,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'sessionName ' + window.localStorage.sessionId
                    }
                }).success(successCallback).error(errorCallback);
            },
            post: function(url, params, data, successCallback, errorCallback) {
                $http({
                    method: 'post',
                    url: url,
                    params: params,
                    data: data,
                    timeout: 15000,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'sessionName ' + window.localStorage.sessionId
                    }
                }).success(successCallback).error(errorCallback);
            },
            delete: function(url, params, successCallback, errorCallback) {
                $http({
                    method: 'delete',
                    url: url,
                    params: params,
                    timeout: 15000,
                    headers: {
                        'Authorization': 'sessionName ' + window.localStorage.sessionId
                    }
                }).success(successCallback).error(errorCallback);
            }
        }
    }])
    .factory('task', ['$http', '$q', 'authentifiedRequest','wizardService', function($http, $q, authentifiedRequest,wizardService) {

        function Task(mac, ip, method, uri, params, data, defer, onCompletelistener) {
            this.mac = mac;
            this.ip = ip;
            this.method = method;
            this.uri = uri;
            this.params = params;
            this.data = data;
            this.defer = defer;
            this.onCompletelistener = onCompletelistener;
        }

        /**
         * clone a task for reverting
         */
        Task.prototype.clone = function() {
            return create(this.mac, this.ip, this.method, this.uri, this.params, this.data, this.onCompletelistener)
        };

        /**
         * execute a task
         */
        Task.prototype.execute = function(time) {
            time = time || 1; //execute times
            var self = this;
            //var scheme = 'http://';
            var scheme = wizardService.getProtocol()+"://";
            var port =":"+wizardService.getPort();
            //var port = ':8080';
            var url = scheme + self.ip + port + self.uri;
                // authentifiedRequest
            var successCallback = function(data, status) {
                //statement execute success
                var res = {
                    'mac': self.mac,
                    'ip': self.ip,
                    'success': true,
                    'msg': 'success'
                };

                if (data == null || data == '') {
                    res.success = false;
                    res.msg = 'log_backendServer_error';
                } else if (!data.success) {
                    res.success = false;
                    res.msg = data.msg;
                }
                self.defer.resolve(res);
            };

            var errorCallback = function(data, status) {
                //statement execute fail  than server return error
                var res = {
                    'mac': self.mac,
                    'ip': self.ip,
                    'success': false,
                    'msg': 'log_backendServer_error'
                };
                self.defer.reject(res);
                //self.defer.reject(self.mac + ' error code=>' + status); //statement execute fail  than server return error code
            };

            switch (self.method) {
                case 'post':
                    authentifiedRequest.post(url, self.params, self.data, successCallback, errorCallback);
                    break;
                case 'put':
                    authentifiedRequest.put(url, self.params, self.data, successCallback, errorCallback);
                    break;
                case 'delete':
                    authentifiedRequest.delete(url, self.params, successCallback, errorCallback);
                    break;
                default:
                    return;

            }

            return self.defer.promise.then(function(res) {
                self.onCompletelistener(res);
            }, function(res) {
                if (time < 3) {
                    time++;
                    // revert the task
                    return self.clone().execute(time);
                } else {
                    // task fail
                    self.onCompletelistener(res);
                    $q.reject(res);
                }
            });
        }

        /**
         * create a task
         */
        function create(mac, ip, method, uri, params, data, onCompletelistener) {
            var task = new Task(mac, ip, method.toLowerCase(), uri, params, data, $q.defer(), onCompletelistener);
            return task;
        }

        return {
            create: create
        }
    }])

/**
 * batch synchronous config
 */
.factory('batchSyncConfig', ['$q','$translate', 'lockScreen', 'task', 'toastr', 'authentifiedRequest', function($q,$translate, lockScreen, task, toastr, authentifiedRequest) {

        /**
         * [tips for user]
         * @param  {[string array]} msgs [string array]
         */
        var tips = function(msgs) {
            var successNum = 0,
                faultNum = 0;
            var successMsg = $translate.instant('log_apNumber_success') +":";
            var faultMsg = $translate.instant('log_apNumber_fault') +":";
            var temp = "";
            angular.forEach(msgs, function(data) {
                if (data.success) {
                    successNum++;
                } else {
                    faultNum++;
                    temp = temp + "<p>IP:" + data.ip + "&nbsp;" +$translate.instant('log_RSN')+ ":" + $translate.instant(data.msg) + "</p>";
                }
            });
            successMsg = "<p>" + successMsg + successNum + '</p>';
            faultMsg = "<p>" + faultMsg + faultNum + '</p>' + temp;

            var title = $translate.instant("log_operateResult")+":";
            toastr.info(successMsg + faultMsg, title);
        };

        //batch  config
        var batchOption = function(method, uri, params, httpData, callbackFunction, haps) {
            var vm = this;
            //the contains store task result
            vm.msgs = [];

            function onCompletelistener(msg) {
                vm.msgs.push(msg);
            }
            var aplist = haps;
            var tasks = [];
            angular.forEach(aplist, function(data) {
                if (data.state == 3 || data.state == 2) { //running/Initializing ap
                    var t = task.create(data.mac, data.ip, method, uri, params, httpData, onCompletelistener);
                    tasks.push(t.execute());
                }
            });

            if (tasks.length == 0) {
                //lock screen delete
                lockScreen.unlock();

                //the notice  has no running ap that can be configged
                                
                var info = $translate.instant("log_noRunningAp_fault");

                toastr.error(info);
              
                if (callbackFunction != null) {
                    callbackFunction();
                }
                return;
            }

            $q.all(tasks).then(function(res) {
                //lock screen delete
                lockScreen.unlock();
                //notice
                tips(vm.msgs)
                //the follow-up operate ,if you have callback ,get callback
                if (callbackFunction != null) {
                    callbackFunction();
                }
            });
        };

        return {
            request: function(method, uri, params, httpData, callbackFunction) {

                //lock screen start
                lockScreen.lock();

                //get aplist
                authentifiedRequest.get("/haps", null, function(data,status) {
                    if(status == 203){// callbackFunction
                        callbackFunction("logout");
                        lockScreen.unlock();
                        return;
                    }

                    if (data != null && data.success) {//the operate after success
                       batchOption(method, uri, params, httpData, callbackFunction,data.result);
                    } else {                     
                        var info = $translate.instant("log_getApList_fault");
                        toastr.info(info);
                        lockScreen.unlock();
                    }

                }, function() {                
                    var info = $translate.instant("log_getApList_fault");
                    toastr.info(info);
                    lockScreen.unlock();
                });

            }
        };
    }])
    /**
     * [lock screen package]
     */
    .factory('lockScreen', ['$timeout', '$rootScope', function($timeout, $rootScope) {
    var timeout = null;

        var time_out_func = function(time){
            if (timeout)
                $timeout.cancel(timeout);

            timeout = $timeout(function() {
                $rootScope.loading = false;
            }, time);
        };

        /**
         * [unlock description]
         */
        var unlock = function() {
            time_out_func(1000);
        };

        /**
         * [lock description]
         */
        var lock = function(timeout) {
            $rootScope.loading = true;
            if(timeout == null){
                time_out_func(15000);
            }else{
                time_out_func(timeout);
            }
        };

        return {
            lock: lock,
            unlock: unlock
        }
    }])
/**
 * [package lock screen ]
 */
.service('hanCrypto', [ function() {
    var vm = this;

    /**
     * encoder
     */
    vm.encoder = function(str) {
        if(str == null || str == ''){
            return str;
        }
        return BASE64.encoder(str);
    };

    /**
     * decoder
     */
    vm.decoder = function(str) {
        if(str == null || str == ''){
            return str;
        }

        var unicode = BASE64.decoder(str);
        var tt = '';
        for(var i = 0 , len =  unicode.length ; i < len ;++i){
              tt += String.fromCharCode(unicode[i]);
        }
        return tt;
    };

}])     

/** wizard params  transfer**/
.factory('wizardService', [function() {
    var userInfo = {
        "username": '',
        "password": ''
    };
    var country = {
        "countryCode":"",
        "timezone":"",
        "city":""
    };
    var countryFlag = false;
    var port = "";
    var protocol = "";
    var ip = "";
    return {
        getIP: function () {
            return ip;
        },
        setIP: function (info) {
            ip = info;
        },
        getPort: function () {
            return port;
        },
        setPort: function (info) {
            port = info;
        },
        getProtocol: function () {
            return protocol;
        },
        setProtocol: function (info) {
            protocol = info
        },
        getUserInfo: function() {
            return userInfo;
        },
        setUsername: function(username) {
            userInfo.username = username;
        },
        setUserpassword: function(password) {
            userInfo.password = password;
        },
        getCountry : function () {
            return country;
        },
        setCountryCode: function (countryCode) {
            country.countryCode = countryCode;
        },
        setCountryFlag: function (flag) {
            countryFlag = flag;
        },
        getCountryFlag: function () {
            return countryFlag;
        },
        setTimezone: function (timezone) {
            country.timezone = timezone;
        },
        setCity: function (city) {
            country.city = city;
        }
    }
}])
.config(['$translateProvider', function($translateProvider){

    //international json file path  in nginx
    $translateProvider.useStaticFilesLoader({
    	prefix: '/static/data/',
    	suffix: '.json'
    });

    $translateProvider.preferredLanguage('en_US');
    $translateProvider.useCookieStorage();
}])
.service('regularExpression', ['$translate',function($translate){
    var vm = this;
    vm.pattern = {
        "ldu4To16": "/^[\\w]{4,16}$/",
        "ldu1To32": "/^[^`=]{1,32}$/",
        "IP": '/^(([1-9])|([1-9]\\d)|(1\\d\\d)|(2[0-4]\\d)|(25[0-5]))(\\.(\\d|([1-9]\\d)|1\\d\\d|2[0-4]\\d|25[0-5])){3}$/',
        "ldu8to63":"/^[^`=\"\']{8,63}$/",
        "Hex64char":"/^[a-fA-F\\d]{64}$/",
       // "exceptBlank1To32": "/^[^\\s]{1,32}$/",
        "exceptBlank1To32": "/^[\\x00-\\xff]{1,32}$/",
        "AuthPort":"/^(^[1-9]\\d{0,3}$)|(^[1-5]\\d{4}$)|(^6[0-4][\\d]{3}$)|(^65[0-4][\\d]{2}$)|(^655[0-2][\\d]|6553[0-5]$)$/"
    };



    vm.errorTip = {
        passNotSame:$translate.instant("passNotSame"),
        validIP: $translate.instant("validIP"),
        Hexchar64:$translate.instant("Hexchar64"),
        "wlanNameTip":$translate.instant("wlanNameTip"),
        adminPassTip: $translate.instant("loginPasswordCheck")
    };
    vm.passNotSame = function () {
        return $translate.instant("passNotSame");
    }
    vm.validIP = function () {
        return $translate.instant("validIP");
    }
    vm.Hexchar64 = function () {
        return $translate.instant("Hexchar64");
    }
    vm.wlanNameTip = function () {
        return $translate.instant("wlanNameTip");
    }
    vm.adminPassTip = function () {
        return $translate.instant("loginPasswordCheck");
    }
    vm.valueNotNull = function(name){
        return $translate.instant("The") + name + $translate.instant("notEmpty");
    };
    vm.lduLengthRangeTip = function(minlength, maxlength){
        return $translate.instant("Please enter") + minlength + $translate.instant("To") + maxlength + $translate.instant("notContain");
    };

    vm.numRange = function(name, startValue, endValue){
        //return "Please input a number between " + startValue + " and " + endValue;
        return $translate.instant("The") + name + $translate.instant("BETWEEN") + startValue + $translate.instant("AND") + endValue;
    };
}])
.directive("repeat", [function () {
    return {
        restrict: 'A',
        require: "ngModel",
        link: function (scope, element, attrs, ctrl) {
            if (ctrl) {
                var otherInput = element.inheritedData("$formController")[attrs.repeat];

                var repeatValidator = function (value) {
                    var validity = value === otherInput.$viewValue;
                    ctrl.$setValidity("repeat", validity);
                    return validity ? value : undefined;
                };

                ctrl.$parsers.push(repeatValidator);
                ctrl.$formatters.push(repeatValidator);

                otherInput.$parsers.push(function (value) {
                    ctrl.$setValidity("repeat", value === ctrl.$viewValue);
                    return value;
                });
            }
        }
    };
}])
;