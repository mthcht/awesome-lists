rule Backdoor_AndroidOS_Vsas_A_2147829034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Vsas.A!MTB"
        threat_id = "2147829034"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Vsas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saveAppData" ascii //weight: 1
        $x_1_2 = "/dpi/gettask.php" ascii //weight: 1
        $x_1_3 = "resp_info" ascii //weight: 1
        $x_1_4 = "Lcom/vsaas/p" ascii //weight: 1
        $x_1_5 = "app.wapx.cn" ascii //weight: 1
        $x_1_6 = "MonitorService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Vsas_B_2147832037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Vsas.B!MTB"
        threat_id = "2147832037"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Vsas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "velocimetry.action" ascii //weight: 1
        $x_1_2 = "com/saasv/app/netspeed" ascii //weight: 1
        $x_1_3 = "resp_info" ascii //weight: 1
        $x_1_4 = "/dpi/register.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

