<?php
    require("fs_waf.php");
    $input = $_GET["evil"];
    fs_waf_scan_exec($input);
    echo $input;
?>