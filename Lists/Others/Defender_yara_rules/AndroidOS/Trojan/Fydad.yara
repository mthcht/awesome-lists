rule Trojan_AndroidOS_Fydad_A_2147813664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fydad.A!MTB"
        threat_id = "2147813664"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fydad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onAdLoaded" ascii //weight: 1
        $x_1_2 = "setAdListener" ascii //weight: 1
        $x_1_3 = "com.vid007.videobuddy" ascii //weight: 1
        $x_1_4 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_5 = "xlCheckAppInstalled" ascii //weight: 1
        $x_1_6 = "callDetailActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

