rule HackTool_AndroidOS_WifiCrack_B_2147797091_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/WifiCrack.B!MTB"
        threat_id = "2147797091"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "WifiCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BruteforceConfigActivity" ascii //weight: 1
        $x_1_2 = "PasswordTester" ascii //weight: 1
        $x_1_3 = "wibr-data.dat" ascii //weight: 1
        $x_1_4 = "bruteforceGenerator" ascii //weight: 1
        $x_1_5 = "Lcz/auradesign/wibrplus/MonitorActivity" ascii //weight: 1
        $x_1_6 = "getTotalPasswords" ascii //weight: 1
        $x_1_7 = "queuePasswordProgress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_WifiCrack_C_2147808782_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/WifiCrack.C!MTB"
        threat_id = "2147808782"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "WifiCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chmod 777 /system/bin/wpa_cli" ascii //weight: 1
        $x_1_2 = "ChoisePin" ascii //weight: 1
        $x_1_3 = "as/wps/wpatester/ShowPassword" ascii //weight: 1
        $x_1_4 = "WpsScan" ascii //weight: 1
        $x_1_5 = "data/misc/wifi/wpa_supplicant.conf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_WifiCrack_D_2147948732_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/WifiCrack.D!MTB"
        threat_id = "2147948732"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "WifiCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wibrplus/MonitorActivity" ascii //weight: 2
        $x_2_2 = "wibrplus/WifiScanActivity" ascii //weight: 2
        $x_1_3 = "WIBR:wifilock" ascii //weight: 1
        $x_1_4 = "Lcz/auradesign/wibrplus/BruteforceGenerator" ascii //weight: 1
        $x_1_5 = "bruteforceGenerator" ascii //weight: 1
        $x_1_6 = "UPDATE bruteforce SET lastPassword=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

