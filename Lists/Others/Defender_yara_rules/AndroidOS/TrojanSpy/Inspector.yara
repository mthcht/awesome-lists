rule TrojanSpy_AndroidOS_Inspector_A_2147820137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Inspector.A!MTB"
        threat_id = "2147820137"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Inspector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "thisisme.thisapp.inspector" ascii //weight: 2
        $x_1_2 = "sendAllSms" ascii //weight: 1
        $x_1_3 = "sendApps" ascii //weight: 1
        $x_1_4 = "sendCallLog" ascii //weight: 1
        $x_1_5 = "sendContact" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

