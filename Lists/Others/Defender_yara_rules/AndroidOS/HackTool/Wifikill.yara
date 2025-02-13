rule HackTool_AndroidOS_Wifikill_A_2147784805_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Wifikill.A!MTB"
        threat_id = "2147784805"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Wifikill"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crap unable to read stuffs" ascii //weight: 1
        $x_1_2 = "Service crashed... died... vaporized... my bad" ascii //weight: 1
        $x_1_3 = "WiFiKill service" ascii //weight: 1
        $x_1_4 = "Killing:" ascii //weight: 1
        $x_1_5 = "paranoid.me" ascii //weight: 1
        $x_1_6 = "hack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Wifikill_B_2147797092_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Wifikill.B!MTB"
        threat_id = "2147797092"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Wifikill"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WiFiKill RUS" ascii //weight: 1
        $x_1_2 = "hack" ascii //weight: 1
        $x_1_3 = "getDhcpInfo" ascii //weight: 1
        $x_1_4 = "paranoid.me/wifikill/downloader" ascii //weight: 1
        $x_1_5 = "getIpAddress" ascii //weight: 1
        $x_1_6 = "Lme/paranoid/wifikill/service/WFKService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Wifikill_C_2147799099_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Wifikill.C!MTB"
        threat_id = "2147799099"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Wifikill"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data/com.tester.wpswpatester" ascii //weight: 1
        $x_1_2 = "misc/wifi/wpa_supplicant.conf" ascii //weight: 1
        $x_1_3 = "WpsScan" ascii //weight: 1
        $x_1_4 = "chmod 777 /system/bin/wpa_cli" ascii //weight: 1
        $x_1_5 = "com/tester/wpswpatester/ShowPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

