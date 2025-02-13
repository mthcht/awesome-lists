rule TrojanSpy_AndroidOS_Smbot_A_2147753802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Smbot.A!MTB"
        threat_id = "2147753802"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Smbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f [0-64] 6d 61 6e 7a 2e 70 68 70}  //weight: 2, accuracy: Low
        $x_1_2 = "content://sms" ascii //weight: 1
        $x_1_3 = "DO NOT INTERRUPT" ascii //weight: 1
        $x_1_4 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 54 65 78 74 4d 65 73 73 61 67 65 28 22 90 02 13 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

