angular.module("monitor", [])
    /**
     * monitorfactory
     */
    .factory('monitorfactory', ['$timeout', function($timeout) {

        /**
         * drow lineChart
         */
        var drowLineChart = function(data, divId, axisLabel,yMax) {
            //set default
            if(yMax == null || yMax == 'undefined'){
                yMax =10;
            }

            nv.addGraph(function() {
                var y_value_array = [];
                // Parse date string to Date and // x/y point's number < 60
                for (var j = 0; j < data.length; ++j) {
                    var temp_values = data[j].values;
                    var num = temp_values.length;
                    if(num > 60){ 
                        temp_values.shift();
                    }

                    for (var i = 0; i < temp_values.length; ++i) {
                        temp_values[i].x = new Date(temp_values[i].x);
                        y_value_array.push(temp_values[i].y);
                        
                    }
                }
                var max_value =  Math.max.apply(null, y_value_array);

                if('undefined' == max_value || max_value < yMax){
                    max_value = yMax;
                }

                var yDomain_array = [0];
                yDomain_array.push(max_value);

                // get max and min dates - this assumes data is sorted

                //init lineChart
                var chart = nv.models.lineChart()
                    .x(function(d) {
                        return d.x;
                    })
                    .y(function(d) {
                        return d.y;
                    })
                    .color(d3.scale.category10().range())
                    .useInteractiveGuideline(true);

                chart.margin({
                    left: 75
                }); //Margin to see yAxis title

                // xAxis configuration
                chart.xAxis
                    .axisLabel(axisLabel)
                    .tickFormat(function(d) {
                        return d3.time.format('%X')(new Date(d))+'\u00a0\u00a0\u00a0\u00a0';
                    });


                // yAxis configuration
                
                chart.yAxis
                    .showMaxMin(true)
                    .tickFormat(function(d) {
                        return d3.format(".1")(d);
                    });

                chart.yDomain(yDomain_array);

                //legend can't click
                chart.legend.updateState(false);

                // draw chart
                d3.select(divId)
                    .datum(data)
                    .transition().duration(500)
                    .call(chart);

                nv.utils.windowResize(chart.update);
                return chart;
            });
        }

        /**
         * drow discreteBarChart
         */
        var drowDiscreteBarChart = function(data, divId, axisLabel) {
            nv.addGraph(function() {
              var chart = nv.models.discreteBarChart()
                  .x(function(d) { return d.label })    //Specify the data accessors.
                  .y(function(d) { return d.value })
                  .color(d3.scale.category10().range())
                  .tooltips(false)        //Don't show tooltips
                  .showValues(true)       //...instead, show the bar value right on top of each bar.
                  .valueFormat(d3.format('.1'));
                  ;
                
                chart.margin({
                    left: 75
                }); //Margin to see yAxis title

                chart.xAxis
                    .axisLabel(axisLabel).labelOffsetMark(true);

                chart.yAxis
                    .showMaxMin(true)
                    .tickFormat(function(d) {
                        return d3.format(".1")(d);
                    });


                var y_value_array = [];
                // Parse date string to Date and // x/y point's number < 60
    
                var values =  data[0].values;        

                for (var j = 0; j < values.length; ++j) {
                    var temp_value = values[j].value;
                    y_value_array.push(temp_value);
                }

                var max_value =  Math.max.apply(null, y_value_array);

                if('undefined' == max_value || max_value < 10){
                    max_value = 10;
                }

                var yDomain_array = [0];
                yDomain_array.push(max_value);

                chart.yDomain(yDomain_array);


              d3.select(divId)
                  .datum(data)
                  .transition().duration(500)
                  .call(chart);
             
              nv.utils.windowResize(chart.update);

              return chart;
            });
        }


        return {
            drowLineChart: drowLineChart,
            drowDiscreteBarChart:drowDiscreteBarChart
        }

    }])
    .service('monitorService', ['$filter', 'batchSyncConfig', 'authentifiedRequest', 'monitorfactory', 'clientService','$translate', function($filter, batchSyncConfig, authentifiedRequest, monitorfactory, clientService,$translate) {
        vm = this;
        //obser and params
        vm.obser = '';
        vm.ap_ip = '';
        vm.ap_mac = '';
        vm.wlan_mac = '';
        vm.client_mac = '';


        /**
         * data defind
         * @type {Array}
         */
        vm.data_throughput = []; //i/o data
        vm.data_cpuAndMem = []; //cpu mem data
        vm.data_client = []; //clientdata
        vm.data_rouge_apAndClient = []; //rouge_apAndClient data
        vm.data_client_speed = []; //client_speed data
        vm.data_client_signal = []; //client_signal data

        /**
         * init
         */
        vm.dataInit = function() {
            var d = new Date();
            d.setSeconds(d.getSeconds() - 10);
            var now = $filter('date')(d, 'yyyy/MM/dd HH:mm:ss');

            vm.data_throughput = [{
                key: $translate.instant("MonitorRX"),
                values: [{'x':now,'y':0}]
            }, {
                key: $translate.instant("MonitorTX"),
                values: [{'x':now,'y':0}]
            }];


            vm.data_cpuAndMem = [{
                key: $translate.instant("Monitorcpu"),
                values: [{'x':now,'y':0}]
            }, {
                key: $translate.instant("Monitormem"),
                values: [{'x':now,'y':0}]
            }];

            vm.data_client = [{
                key:$translate.instant("MonitorSmallClient"),
                values: [{'x':now,'y':0}]
            }];

            vm.data_rouge_apAndClient = [{
                key: $translate.instant("MonitorRouge"),
                values: [{'x':now,'y':0}]
            }, {
                key:$translate.instant("MonitorInter"),
                values: [{'x':now,'y':0}]
            }];

            vm.data_client_speed = [{
                key: $translate.instant("MonitorRX"),
                values: [{'x':now,'y':0}]
            }, {
                key:$translate.instant("MonitorTX"),
                values: [{'x':now,'y':0}]
            }];

            vm.data_client_signal = [{
                key:$translate.instant("MonitorSmallRSSI"),
                values: [{'x':now,'y':0}]
            }];

            vm.data_client_band = [{
                key: $translate.instant("MonitorBarChar"),
                values: [
                    {'label':'2.4GHz','value':0},
                    {'label':'5GHz','value':0}]
            }];

            vm.data_client_health = [{
                key:$translate.instant("MonitorBarChar"),
                values: [
                    {'label':$translate.instant("MonitorBest"),'value':0},
                    {'label':$translate.instant("MonitorGood"),'value':0},
                    {'label':$translate.instant("MonitorFair"),'value':0}]
            }];

        };

        /**
         * drowClusterCpuAndMemLineChart
         */
        vm.drowClusterCpuAndMemLineChart = function(divId) {
            batchSyncConfig.getAll('/monitor/cpuAndMemUsage', null, function(resultArray) {
                var num = resultArray.length;
                if (num != 0) {
                    var obj = resultArray;
                    var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss'); 

                    var cpuNum = 0;
                    var memNum = 0;

                    angular.forEach(obj, function(data) {
                        cpuNum = cpuNum + parseInt(data.cpu);
                        memNum = memNum + parseInt(data.mem);
                    });

                    cpuNum = Math.floor(cpuNum / num);
                    memNum = Math.floor(memNum / num);

                    //add cpu
                    var cpu_values = vm.data_cpuAndMem[0].values;
                    var new_cpu_data = new Array();
                    new_cpu_data['x'] = now;
                    new_cpu_data['y'] = cpuNum;
                    cpu_values.push(new_cpu_data);

                    //remove mem
                    var mem_values = vm.data_cpuAndMem[1].values;

                    var new_mem_data = new Array();
                    new_mem_data['x'] = now;
                    new_mem_data['y'] = memNum;
                    mem_values.push(new_mem_data);
                }

                //change
                monitorfactory.drowLineChart(vm.data_cpuAndMem, divId,$translate.instant("MonitorCpu"),null);

            });
        }

        /**
         * drowSingleApCpuAndMemLineChart
         */
        vm.drowSingleApCpuAndMemLineChart = function(apIp, divId) {
			var scheme = InterService.getProtocol()+"://";
			//var scheme = 'http://';
            var port = ":"+InterService.getPort();
            //var port = ':8080';
            var url = scheme + apIp + port + "/monitor/cpuAndMemUsage";
            authentifiedRequest.request('get', url, null, null, 15000, function(data) {
                if (data != null && data.success) {
                    var obj = data.result;
                    var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss'); 
                    //add cpu
                    var cpu_values = vm.data_cpuAndMem[0].values;
                    var new_cpu_data = new Array();
                    new_cpu_data['x'] = now;
                    new_cpu_data['y'] = obj.cpu;
                    cpu_values.push(new_cpu_data);

                    //add mem
                    var mem_values = vm.data_cpuAndMem[1].values;

                    var new_mem_data = new Array();
                    new_mem_data['x'] = now;
                    new_mem_data['y'] = obj.mem;
                    mem_values.push(new_mem_data);
                }
                monitorfactory.drowLineChart(vm.data_cpuAndMem, divId, $translate.instant("MonitorCpu"),null);
            }, function() {
            
            });
        };

        /**
         *drowSingleApRogueApLineChart
         */
        vm.drowSingleApRogueApLineChart = function(apIp, divId) {
			var scheme = 'http://';
            var port = ':8080';
            var url = scheme + apIp + port + "/monitor/rogueApAndClient";
            authentifiedRequest.request('get', url, null, null, 15000, function(data) {
                if (data != null && data.success) {
                    var obj = data.result;
                    var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss'); 
                    //add rogue_ap_num
                    var key1 = vm.data_rouge_apAndClient[0].values;
                    var new_a = new Array();
                    new_a['x'] = now;
                    new_a['y'] = obj.rogue_ap_num;
                    key1.push(new_a);

                    //add interfering_ap_num
                    var key2 = vm.data_rouge_apAndClient[1].values;
                    var new_b = new Array();
                    new_b['x'] = now;
                    new_b['y'] = obj.interfering_ap_num;
                    key2.push(new_b);

                }
                monitorfactory.drowLineChart(vm.data_rouge_apAndClient, divId, $translate.instant("MonitorRogueAP"),null);

            }, function() {

            });

        };

        /**
         * drowThroughputLineChart
         * */
        vm.drowThroughputLineChart = function(mac, divId) {
            var clients = clientService.getClientList();

            var outputFlow = 0;
            var inputFlow = 0;


            //js float sum
            var pushData = function(data) { 
                outputFlow = (outputFlow*100 + Number(data.UPRATE)*100)/100;
                inputFlow = (inputFlow*100 + Number(data.DOWNRATE)*100)/100;
            }
 
            angular.forEach(clients, function(data) {
                if (vm.obser == 'cluster') {
                    pushData(data);
                } else if (vm.obser == 'wlan' && data.WLAN == mac) {
                    pushData(data);
                } else if (vm.obser == 'ap' && data.AP == mac) {
                    pushData(data);
                } else if (vm.obser == 'client' && data.UserMAC == mac) {
                    pushData(data);
                }
            });

            //add data
            var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss');       

            var key1 = vm.data_throughput[0].values;
            //add rx
            var new_a = new Array();
            new_a['x'] = now;
            new_a['y'] = outputFlow.toFixed(2);
            key1.push(new_a);

            //add tx
            var key2 = vm.data_throughput[1].values;

            var new_b = new Array();
            new_b['x'] = now;
            new_b['y'] = inputFlow.toFixed(2);
            key2.push(new_b);

            monitorfactory.drowLineChart(vm.data_throughput, divId, $translate.instant("MonitorThroughout"),1);

        };

        /**
         * drowClientsLineChart
         */
        vm.drowClientsLineChart = function(mac, divId) {

            var clients = clientService.getClientList();
            var clientNum = 0;

            if (vm.obser == 'cluster') {
                clientNum = clients.length;
            } else {
                angular.forEach(clients, function(data) {
                    if (vm.obser == 'wlan' && data.WLAN == mac) {
                        clientNum++;
                    } else if (vm.obser == 'ap' && data.AP == mac) {
                        clientNum++;
                    }
                });
            }

            //add client num
            var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss');
            var key1 = vm.data_client[0].values;
            var new_a = new Array();
            new_a['x'] = now;
            new_a['y'] = clientNum;
            key1.push(new_a);

            monitorfactory.drowLineChart(vm.data_client, divId, $translate.instant("MonitorClient"),null);

        };


        /**
         * drowSpeedLineChart
         */
        vm.drowSpeedLineChart = function(mac, divId) {

            var clients = clientService.getClientList();

            var rxrate = 0;
            var txrate = 0;

            angular.forEach(clients, function(data) {
                if (vm.obser == 'client' && data.UserMAC == mac) {
                    rxrate = Number(data.RXRATE);
                    txrate = Number(data.TXRATE);
                }
            });

            //add data
            var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss'); 

            var rx_values = vm.data_client_speed[0].values;
            //add speed rx
            var new_rx = new Array();
            new_rx['x'] = now;
            new_rx['y'] = rxrate;
            rx_values.push(new_rx);

            //add speed tx
            var tx_values = vm.data_client_speed[1].values;
            var new_tx = new Array();
            new_tx['x'] = now;
            new_tx['y'] = txrate;
            tx_values.push(new_tx);

            monitorfactory.drowLineChart(vm.data_client_speed, divId, $translate.instant("MonitorPHY"),null);
        };

        /**
         * drowRSSILineChart
         */
        vm.drowRSSILineChart = function(mac, divId) {

            var clients = clientService.getClientList();

            var rssi = 0;

            angular.forEach(clients, function(data) {
                if (vm.obser == 'client' && data.UserMAC == mac) {
                    rssi = data.RSSI;
                }
            });

            //add data
            var now = $filter('date')(new Date(), 'yyyy/MM/dd HH:mm:ss');   
            var rssi_values = vm.data_client_signal[0].values;
            //add speed rx
            var new_rssi = new Array();
            new_rssi['x'] = now;
            new_rssi['y'] = rssi;
            rssi_values.push(new_rssi);

            monitorfactory.drowLineChart(vm.data_client_signal, divId, $translate.instant("MonitorRSSI"),null);

        };

        /**
         * drow ClientBandBarChart
         * */
        vm.drowClientBandBarChart = function(divId,mac) {
            var clients = clientService.getClientList();

            var v1 = 0;
            var v2 = 0;

            var modifyBand = function(data) { 
                if(data == '2.4ghz'){
                    v1 +=1;
                }else if(data == '5ghz'){
                    v2 +=1;
                }
            };

            angular.forEach(clients, function(data) {
                var freq = data.FREQ.toLowerCase();
                if (vm.obser == 'cluster' || 
                    (vm.obser == 'wlan' && data.WLAN == mac) ||
                    (vm.obser == 'ap' && data.AP == mac)) {

                    modifyBand(freq);
                }

            });

            //set data
            var values =  vm.data_client_band[0].values;
            var band2obj = values[0];
            band2obj.value = v1;
            var band5obj = values[1];
            band5obj.value = v2;
            monitorfactory.drowDiscreteBarChart(vm.data_client_band, divId,$translate.instant("MonitorClientBand"));

        };

        /**
         * drow drowClientHealthBarChart
         * */
        vm.drowClientHealthBarChart = function(divId,mac) {
            var clients = clientService.getClientList();

            var best = 0;
            var good = 0;
            var fair = 0;

            var modifyHealth = function(data) { 
               if (data <-75) {
                    fair +=1;
                }else if (data >-60) {
                    best +=1;
                }else{
                    good +=1;
                }
            };
            angular.forEach(clients, function(data) {
                var rssi = parseInt(data.RSSI) - 95;
                if (vm.obser == 'cluster' || 
                    (vm.obser == 'wlan' && data.WLAN == mac) ||
                    (vm.obser == 'ap' && data.AP == mac)) {
                    
                    modifyHealth(rssi);
                }

            });

            //set data
 
            var values =  vm.data_client_health[0].values;

            var bestObj = values[0];
            bestObj.value = best;
            var goodObj = values[1];
            goodObj.value = good;
            var fairObj = values[2];
            fairObj.value = fair;            
        
            monitorfactory.drowDiscreteBarChart(vm.data_client_health, divId,$translate.instant("MonitorClientHealth"));

        };        

        /**
         * updateChartview
         */
        vm.updateChartview = function() {

            if ('wlan' == vm.obser) {
                //Throughput
                vm.drowThroughputLineChart(vm.wlan_ssid, '#cluster_chart5 svg');

                //client
                vm.drowClientsLineChart(vm.wlan_ssid, '#cluster_chart6 svg');

                //client Band BarChart
                vm.drowClientBandBarChart('#cluster_chart7 svg',vm.wlan_ssid);

                //client Health BarChart
                vm.drowClientHealthBarChart('#cluster_chart8 svg',vm.wlan_ssid);


            } else if ('client' == vm.obser) {

                //Throughput
                vm.drowThroughputLineChart(vm.client_mac, '#cluster_chart5 svg');

                //rxrate/txrate  Signal(Rssi)
                vm.drowRSSILineChart(vm.client_mac, '#cluster_chart6 svg');

                vm.drowSpeedLineChart(vm.client_mac, '#cluster_chart7 svg');

            } else if ('ap' == vm.obser) {

                //Throughput
                vm.drowThroughputLineChart(vm.ap_mac, '#cluster_chart5 svg');

                //client
                vm.drowClientsLineChart(vm.ap_mac, '#cluster_chart6 svg');

                //cpu/mem
                //vm.drowSingleApCpuAndMemLineChart(vm.ap_ip, '#cluster_chart7 svg');

                //rogue ap
                //vm.drowSingleApRogueApLineChart(vm.ap_ip, '#cluster_chart8 svg');
                
                //client Band BarChart
                vm.drowClientBandBarChart('#cluster_chart7 svg',vm.ap_mac);

                //client Health BarChart
                vm.drowClientHealthBarChart('#cluster_chart8 svg',vm.ap_mac);

            } else if ('cluster' == vm.obser) {

                //Throughput 
                vm.drowThroughputLineChart(null, '#cluster_chart5 svg');

                //client 
                vm.drowClientsLineChart(null, '#cluster_chart6 svg');

                //cpu/mem
                //vm.drowClusterCpuAndMemLineChart('#cluster_chart7 svg');

                //client Band BarChart
                vm.drowClientBandBarChart('#cluster_chart7 svg',null);

                //client Health BarChart
                vm.drowClientHealthBarChart('#cluster_chart8 svg',null);
            }

        };

        /**
         * change Obser
         */
        vm.changeObser = function(t_obser, param, title) {

            // svgÔªËØÄÚÈÝÇå¿Õ
            d3.select("#cluster_chart5 svg").remove();
            d3.select("#cluster_chart5").append("svg");

            d3.select("#cluster_chart6 svg").remove();
            d3.select("#cluster_chart6").append("svg");

            d3.select("#cluster_chart7 svg").remove();
            d3.select("#cluster_chart7").append("svg");

            d3.select("#cluster_chart8 svg").remove();
            d3.select("#cluster_chart8").append("svg");
            d3.select("#viewer_title").text(title);

            //clean param
            vm.wlan_ssid = '';
            vm.ap_ip = '';
            vm.ap_mac = '';
            vm.client_mac = '';

            //clean chart data
            vm.dataInit();

            //set param
            vm.obser = t_obser;
            if ('wlan' == vm.obser) {
                vm.wlan_ssid = param;
            } else if ('client' == vm.obser) {
                vm.client_mac = param;
            } else if ('ap' == vm.obser) {
                vm.ap_ip = param.ip;
                vm.ap_mac = param.mac;
            } else if ('cluster' == vm.obser) {

            }

            //update
            vm.updateChartview();
        };


    }])

.controller("monitorController", [function() {
    //do nothing

}])