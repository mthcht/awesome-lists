rule Trojan_AndroidOS_SaveStealer_G_2147902070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SaveStealer.G!MTB"
        threat_id = "2147902070"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SaveStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/hello/topfffw" ascii //weight: 1
        $x_1_2 = "growtopia" ascii //weight: 1
        $x_1_3 = "webhookurl" ascii //weight: 1
        $x_1_4 = "savedat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

