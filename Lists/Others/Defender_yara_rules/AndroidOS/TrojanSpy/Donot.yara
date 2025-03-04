rule TrojanSpy_AndroidOS_DoNot_A_2147836761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DoNot.A!MTB"
        threat_id = "2147836761"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DoNot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/hello/upload" ascii //weight: 1
        $x_1_2 = "com/system/android/updater/ten" ascii //weight: 1
        $x_1_3 = "alraddorn" ascii //weight: 1
        $x_1_4 = "WappFileSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_DoNot_A_2147836761_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DoNot.A!MTB"
        threat_id = "2147836761"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DoNot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSms_dt" ascii //weight: 1
        $x_1_2 = "Keylogs" ascii //weight: 1
        $x_1_3 = "sr_tm_dur" ascii //weight: 1
        $x_1_4 = "live_rec1_dttm" ascii //weight: 1
        $x_1_5 = "wtsp_rec" ascii //weight: 1
        $x_1_6 = "wa_date_id" ascii //weight: 1
        $x_1_7 = "KYLK00.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

