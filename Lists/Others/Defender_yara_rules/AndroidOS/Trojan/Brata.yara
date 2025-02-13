rule Trojan_AndroidOS_Brata_A_2147822771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Brata.A"
        threat_id = "2147822771"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Brata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_wsh_connecttoyou" ascii //weight: 1
        $x_1_2 = "_wsh_setkeylogapp" ascii //weight: 1
        $x_1_3 = "_wsh_loadkeylogdata" ascii //weight: 1
        $x_1_4 = "_wsh_sendclicks" ascii //weight: 1
        $x_1_5 = "_wsh_openapp" ascii //weight: 1
        $x_1_6 = "_wsh_disconnectedfromadmin" ascii //weight: 1
        $x_1_7 = "_wsh_openrecentsapps" ascii //weight: 1
        $x_1_8 = "_wsh_formatthisdevice" ascii //weight: 1
        $x_1_9 = "_wsh_sendsctome" ascii //weight: 1
        $x_1_10 = "_wsh_clickonaddlock" ascii //weight: 1
        $x_1_11 = "_wsh_startscroll" ascii //weight: 1
        $x_1_12 = "_wsh_uninstallapp" ascii //weight: 1
        $x_1_13 = "_wsh_sendsmsmessages" ascii //weight: 1
        $x_1_14 = "_wsh_wakeupphone" ascii //weight: 1
        $x_1_15 = "_wsh_sendsmsmessagestonumber" ascii //weight: 1
        $x_1_16 = "_send_socket_data" ascii //weight: 1
        $x_1_17 = "_load_allappsdata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_AndroidOS_Brata_B_2147822772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Brata.B"
        threat_id = "2147822772"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Brata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startactdevmang" ascii //weight: 1
        $x_1_2 = "startactgpper" ascii //weight: 1
        $x_1_3 = "startactoverlay" ascii //weight: 1
        $x_1_4 = "startsmspermnew" ascii //weight: 1
        $x_1_5 = "startactwritesy" ascii //weight: 1
        $x_1_6 = "startscreencap" ascii //weight: 1
        $x_1_7 = "takescreenshot" ascii //weight: 1
        $x_1_8 = "trackggppss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Brata_C_2147822773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Brata.C"
        threat_id = "2147822773"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Brata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_pmsetcomponentenabledsetting" ascii //weight: 1
        $x_1_2 = "_candrawoverlays" ascii //weight: 1
        $x_1_3 = "_canwritetosystemsettings" ascii //weight: 1
        $x_1_4 = "_activateallperms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

