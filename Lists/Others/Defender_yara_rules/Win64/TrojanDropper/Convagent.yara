rule TrojanDropper_Win64_Convagent_BH_2147825866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Convagent.BH!MTB"
        threat_id = "2147825866"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c2 48 8d 4d cf 48 03 c8 8d 42 13 ff c2 30 01 83 fa 18 72}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 c8 48 8d 54 24 40 48 8d 14 4a 41 8d 0c 01 ff c0 66 31 0a 83 f8 13 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_Convagent_MK_2147957471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Convagent.MK!MTB"
        threat_id = "2147957471"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {30 94 c3 9f 3e e3 ef 08 b6 f7 71 68 a1 32 3c ce ff c9 d0 e3 0f 02 d9 86 95 32 ba c2 ee 3b 26}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

