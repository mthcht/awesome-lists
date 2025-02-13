rule MonitoringTool_AndroidOS_MobileTx_A_353353_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileTx.A!MTB"
        threat_id = "353353"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileTx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HIDE_AD" ascii //weight: 1
        $x_1_2 = "TxActivity" ascii //weight: 1
        $x_1_3 = "doShoewAd" ascii //weight: 1
        $x_1_4 = "LoadAdTask" ascii //weight: 1
        $x_1_5 = "craetThreadLoadAD" ascii //weight: 1
        $x_5_6 = {4c 63 6f 6d 2f 74 78 2f [0-16] 2f 56 61 6c 69 64 61 74 65 41 73 79 6e 63 54 61 73 6b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_MobileTx_B_353531_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileTx.B!MTB"
        threat_id = "353531"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileTx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mobile.tx.com.cn:8081/client/reg.do" ascii //weight: 1
        $x_1_2 = "/sdcard/app/tx/root" ascii //weight: 1
        $x_1_3 = "txconfig/menu.json" ascii //weight: 1
        $x_1_4 = "getPhonenum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

