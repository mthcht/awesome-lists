rule TrojanSpy_AndroidOS_ServcRAT_A_2147822881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/ServcRAT.A!MTB"
        threat_id = "2147822881"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "ServcRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 72 65 76 65 72 73 65 73 68 65 6c 6c [0-3] 2f 50 61 79 6c 6f 61 64 73 2f 6e 65 77 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "hideAppIcon" ascii //weight: 1
        $x_1_3 = "getPhoneNumber" ascii //weight: 1
        $x_1_4 = "get_numberOfCameras" ascii //weight: 1
        $x_1_5 = "getCallLogs" ascii //weight: 1
        $x_1_6 = "getSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

