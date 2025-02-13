rule Backdoor_MacOS_ObjCShellZ_A_2147899668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ObjCShellZ.A!MTB"
        threat_id = "2147899668"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ObjCShellZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swissborg.b" ascii //weight: 1
        $x_1_2 = "log/zxcv/bnm" ascii //weight: 1
        $x_1_3 = "operatingSystemVersionString" ascii //weight: 1
        $x_1_4 = "Command executed successfully" ascii //weight: 1
        $x_1_5 = "sendRequest" ascii //weight: 1
        $x_1_6 = "setTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_ObjCShellZ_B_2147899669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ObjCShellZ.B!MTB"
        threat_id = "2147899669"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ObjCShellZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swissborg.blog/zxcv/bnm" ascii //weight: 1
        $x_1_2 = "setHTTPMethod" ascii //weight: 1
        $x_1_3 = "Command executed" ascii //weight: 1
        $x_1_4 = "mainRunLoop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

