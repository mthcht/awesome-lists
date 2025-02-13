rule TrojanSpy_AndroidOS_GodFather_A_2147816667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GodFather.A!MTB"
        threat_id = "2147816667"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GodFather"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callForward" ascii //weight: 1
        $x_1_2 = "SendNewUser" ascii //weight: 1
        $x_1_3 = "SendKeylog" ascii //weight: 1
        $x_1_4 = "linkopen" ascii //weight: 1
        $x_1_5 = "isEmulator" ascii //weight: 1
        $x_1_6 = "SendUSD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

