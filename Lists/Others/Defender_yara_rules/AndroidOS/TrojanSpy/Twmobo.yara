rule TrojanSpy_AndroidOS_Twmobo_A_2147797018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Twmobo.A"
        threat_id = "2147797018"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Twmobo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 53 35 30 10 00 48 03 05 00 21 14 94 04 00 04 48 04 01 04 b7 43 8d 33 4f 03 02 00 d8 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "ND_DUMP" ascii //weight: 1
        $x_1_3 = "hwid" ascii //weight: 1
        $x_1_4 = "transport is open - connecting" ascii //weight: 1
        $x_1_5 = "gerenciar apps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Twmobo_C_2147809491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Twmobo.C!MTB"
        threat_id = "2147809491"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Twmobo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {21 53 35 31 10 00 48 03 05 01 21 64 94 04 01 04 48 04 06 04 b7 43 8d 33 4f 03 02 01 d8 01 01 01 28 f0}  //weight: 3, accuracy: High
        $x_1_2 = "ND_DUMP" ascii //weight: 1
        $x_1_3 = "c7f3f5dcad84eeaea64e40dca4a2e2f5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

