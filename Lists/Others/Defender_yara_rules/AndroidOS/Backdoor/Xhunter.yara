rule Backdoor_AndroidOS_Xhunter_A_2147834441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Xhunter.A!MTB"
        threat_id = "2147834441"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Xhunter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/xhunter/client" ascii //weight: 1
        $x_1_2 = "sendDataToServer" ascii //weight: 1
        $x_1_3 = "downloadWhatsappDatabase" ascii //weight: 1
        $x_1_4 = "getInstalledApps" ascii //weight: 1
        $x_1_5 = "xhunterTest" ascii //weight: 1
        $x_1_6 = "slackhook" ascii //weight: 1
        $x_1_7 = "sendSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Xhunter_B_2147844110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Xhunter.B!MTB"
        threat_id = "2147844110"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Xhunter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.xhunter.client" ascii //weight: 1
        $x_1_2 = "xhunterTest" ascii //weight: 1
        $x_1_3 = "<++++++++++++++++><><>><<<<>Successfully started myself++++>>>>>>>>" ascii //weight: 1
        $x_1_4 = "sendDataToServer" ascii //weight: 1
        $x_1_5 = "getinstalledapps" ascii //weight: 1
        $x_1_6 = "downloadWhatsappDatabase" ascii //weight: 1
        $x_1_7 = "readCallLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

