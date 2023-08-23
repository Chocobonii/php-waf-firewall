<?php
    /*
    ***************************************************************************
    *        *                                                   *            *
    *       *                                                     *           *
    *     **                                                       **         *
    * *   **                                                       **   *     *
    * **   **          *                               *          **   **     *
    * ***    *         **                             **         *    ***     *
    * ****            *********************************            ****       *
    *    *******      ***           *******           ***      *******        *
    *       ************             *****             ************           *
    *          **********    **** * **   ** *******   **********              * 
    *                ********** ** **     ** ****************                 *
    *          *************** ** **  ***  **  *****************              *
    *           ******   *********************  ******   ******               *
    *                     **********************  ***                         *
    *                     ************************ **                         *
    *                      **** ** ** **** ** ** **                           *
    *                       ***  *  *  **  *  *  ***                          *
    *                        **                  **                           *
    *                          *                *                             *
    *     ___ _               _                         __    __  _      ___  *
    *    / __(_)_ __ ___  ___| |_ ___  _ __ _ __ ___   / / /\ \ \/_\    / __\ *
    *   / _\ | | '__/ _ \/ __| __/ _ \| '__| '_ ` _ \  \ \/  \/ //_\\  / _\   *
    *  / /   | | | |  __/\__ \ || (_) | |  | | | | | |  \  /\  /  _  \/ /     *
    *  \/    |_|_|  \___||___/\__\___/|_|  |_| |_| |_|   \/  \/\_/ \_/\/      * 
    ***************************************************************************                                                                
    */
    ini_set('display_errors', 0); 
    $ip = "";
    // - = = LOAD ALL THE PAYLOADS FOR THE SYSTEM = = -
    $payloads = array();
    $fn = fopen("./local_payloads/all.txt","r");
  
    while(! feof($fn))  {
        $attack = fgets($fn);
        $attack = str_replace("/\r|\n/", '', $attack);
        $result = bin2hex($attack); // let's convert the payloads into hex, to avoid attacks to the WAF
        array_push($payloads, "" . $result);
        //echo $result . "<br>";
    }
    //print_r($payloads);
    fclose($fn);
    // -----------------------------------------------------------
    $ip_ptr = 0; // this hardcoded IP is just for testing purposes
    $ban_list = array("10.10.10.10");
    
    $rfn = fopen("banned.txt","r"); // TODO: PLEASE REMEMBER TO CREATE THIS FILE!!!!!!!!!!!!!!!!

    while(! feof($rfn))  {
        $dresult = fgets($rfn);  
        $dresult = bin2hex($dresult);
        $dresult = str_replace("0a", '', $dresult);
        
        array_push($ban_list, $dresult);
        //echo $result;
    }
 
    //fclose($rfn);
    // -----------------------------------------------------------------
    function fs_payload_broker($string) {
        $string = preg_replace('/[^A-Za-z0-9$\/=]/', '-', $string);
        $string = str_replace(' ', '-', $string);   // AT FIRST THIS IS A SMALL PAYLOAD BROKER
        $string = str_replace('$', '-', $string);   // IT WILL CLEAN UP ALL OF THE POTENTIAL
        $string = str_replace('\'', '-', $string);  // PAYLOADS THAT THE ATTACKER SENDS
        $string = str_replace('\"', '-', $string);  // 
        return preg_replace('/-+/', '-', $string);  // BASICALLY, STRING SANITIZATION
    }                                               // 
    // ----------------------------------------------------------------
    function fs_payload_blocker($string){
        global $payloads;
        $string = bin2hex($string);
         
        foreach($payloads as $key => $attack){
            $attack = str_replace("0a", '', $attack);
            //echo "compare: " . $string . " with " . $attack . "<br>";
            if (str_contains($string, $attack)) {
                return true;
            }
        }
        return false;
    }
    // ----------------------------------------------------------------
    function fs_ban_user_ip ($user_ip) {            // 
        global $ban_list;                           //
        array_push($ban_list, bin2hex($user_ip));   // THIS PUSHES AN IP ADDRESS TO A BAN LIST
    }                                               // 
    // ----------------------------------------------------------------
    function fs_ban_ip_range($base, $min, $max){    // 
        global $ban_list;                           //
        for($i = $min; $i < $max; $i = $i + 1 ){    // THESE ARE THE EQUIVALENT TO IPTABLES
            $ban = "" . $base . $i;                 // 
            array_push($ban_list, bin2hex($ban));   // BASICALLY IT BANS A RANGE OF IP ADDRESSES
        }                                           // 
    }                                               // 
    // ----------------------------------------------------------------
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {               // 
        $ip = $_SERVER['HTTP_CLIENT_IP'];                   // NOW FOR THE IP BANNING SYSTEM TO WORK
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {   // WE NEED TO GET THE REMOTE CLIENT IP
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];             // ADDRESS, AND AS WE ARE ON THE SERVERSIDE
    } else {                                                // WE CAN ACTUALLY DO THAT, SO WE CALL THE
        $ip = $_SERVER['REMOTE_ADDR'];                      // IP ADDRESS, AND LOOK IF ITS ON THE BANNED POOL
    }                                                       // 
    // -----------------------------------------------------------------
    $ip = bin2hex($ip);

    if(in_array($ip, $ban_list)){                           // 
        die('You are banned from this server');             // THIS IP HAS BEEN BANNED FROM A SERVER
    }                                                       // 
    // -----------------------------------------------------------------
    function fs_waf_scan_exec($user_input){
        global $ip;
        $found_attacks = 0;
        $has_payload = fs_payload_blocker($user_input);
        //echo "attack: " . $has_payload . "<br>";
        if($has_payload){
            $found_attacks = $found_attacks + 1;
        }
        $safe = fs_payload_broker($user_input);
        if($found_attacks > 0){
            fs_ban_user_ip($ip);
            $sfp = fopen('banned.txt', 'a');
            if($sfp){
                //echo 'open';
                fwrite($sfp, "\n" . $ip);
                fclose($sfp);
            }else{
                echo 'failed to open file, please check permissions';
            }
            echo "<h1>400 BAD REQUEST</h1><br>";
            die("You are banned from this server.");
        }
        return $safe;
    }
    //echo 'complete';
?>