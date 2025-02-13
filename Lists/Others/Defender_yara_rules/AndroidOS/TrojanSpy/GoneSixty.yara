rule TrojanSpy_AndroidOS_GoneSixty_A_2147649954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GoneSixty.A"
        threat_id = "2147649954"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GoneSixty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.gone60.gone60.refresh" ascii //weight: 1
        $x_1_2 = "Uploading to gi60s.com.." ascii //weight: 1
        $x_1_3 = "Lcom/gone60/gone60$DataUpdateReceiver" ascii //weight: 1
        $x_1_4 = "android.intent.action.DELETE" ascii //weight: 1
        $x_1_5 = "textview_contacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

