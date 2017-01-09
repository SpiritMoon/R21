<?php
/**
 * Step 1: Require the Slim Framework
 *
 * If you are not using Composer, you need to require the
 * Slim Framework and register its PSR-0 autoloader.
 *
 * If you are using Composer, you can skip this step.
 */
require 'Slim/Slim.php';

\Slim\Slim::registerAutoloader();

/**
 * Step 2: Instantiate a Slim application
 *
 * This example instantiates a Slim application using
 * its default settings. However, you will usually configure
 * your Slim application now by passing an associative array
 * of setting names and values into the application constructor.
 */
$app = new \Slim\Slim();
$app->response->headers->set('Content-Type', 'application/json');
$app->response->headers->set('Cache-Control', 'no-cache, must-revalidate');
$app->response->headers->set('Access-Control-Allow-Origin', '*');
$app->response->headers->set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
$app->response->headers->set('Access-Control-Max-Age', 3600);
$app->response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With');


$app->options('/:any+', function($any) use ($app){
      $app->response->setStatus(204);
});

/**
 * Step 3: Define the Slim application routes
 *
 * Here we define several Slim application routes that respond
 * to appropriate HTTP request methods. In this example, the second
 * argument for `Slim::get`, `Slim::post`, `Slim::put`, `Slim::patch`, and `Slim::delete`
 * is an anonymous function.
 */
 /** hooks **/
require 'src/com/han/common/hanlet_hook.php';
require 'src/com/han/common/Crypto.php';

/** network **/
require 'src/com/han/network/igmp_snooping_controller.php';
require 'src/com/han/network/arp_proxy_controller.php';
require 'src/com/han/network/ntp_controller.php';
require 'src/com/han/network/WMM_controller.php';

/****
* wlan wireless syslog
* edit by qiaojie
**/
require 'src/com/han/wireless/rfManagement.php';
require 'src/com/han/wireless/rogueAp.php';
require 'src/com/han/wireless/others.php';
require 'src/com/han/wlan/wlan.php';
require 'src/com/han/system/syslog.php';

/****
* edit by dt
**/
require 'src/com/han/ap/aplist.php';
require 'src/com/han/ap/apcluster.php';

/****
* client and access
**/
require 'src/com/han/client/client_controller.php';
require 'src/com/han/terminal/aclconf_controller.php';
require 'src/com/han/terminal/authview_controller.php';
require 'src/com/han/terminal/authconf_controller.php';
require 'src/com/han/terminal/access_controller.php';

 /** common **/
require 'src/com/han/common/CommonFunction.php';
require 'src/com/han/common/authentication_controller.php';

 /** other **/
require 'src/com/han/other/wizard_controller.php';
require 'src/com/han/other/tools_controller.php';

 /** monitor **/
require 'src/com/han/monitor/monitor_controller.php';

/**
 * Step 4: Run the Slim application
 *
 * This method should be called last. This executes the Slim application
 * and returns the HTTP response to the HTTP client.
 */
$app->run();

?>