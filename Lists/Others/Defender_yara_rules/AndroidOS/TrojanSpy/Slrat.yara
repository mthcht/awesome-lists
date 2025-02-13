rule TrojanSpy_AndroidOS_Slrat_A_2147754744_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Slrat.A!MTB"
        threat_id = "2147754744"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Slrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.slh4ck3r.slrat" ascii //weight: 1
        $x_1_2 = "device_admin_disabled" ascii //weight: 1
        $x_1_3 = "/system/app/com.slh4ck3r.slrat.apk" ascii //weight: 1
        $x_1_4 = "SL_H4CK3R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

