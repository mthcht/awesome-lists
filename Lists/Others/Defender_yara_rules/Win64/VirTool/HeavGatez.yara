rule VirTool_Win64_HeavGatez_A_2147839555_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HeavGatez.A!MTB"
        threat_id = "2147839555"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HeavGatez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 89 44 24 20 4c 8d ?? ?? ?? ?? ?? 4c 8b 85 28 02 00 00 ba 05 00 00 00 48 8b 4d 68 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 05 b2 c0 00 00 83 c0 46 8b c0 48 8b 8d 40 01 00 00 48 89 08 8b 05 9d c0 00 00 83 c0 56 8b c0}  //weight: 1, accuracy: High
        $x_1_3 = {8b 05 b2 c0 00 00 83 c0 46 8b c0 48 8b 8d 40 01 00 00 48 89 08}  //weight: 1, accuracy: High
        $x_1_4 = {48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 80 00 00 00 48 c7 44 24 30 01 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 40 4c 8d ?? ?? ?? ?? ?? ba 07 00 00 00 48 8b 4d 48 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c0 b9 64 00 00 00 f3 aa 48 8d ?? ?? ?? ?? ?? b9 04 01 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

