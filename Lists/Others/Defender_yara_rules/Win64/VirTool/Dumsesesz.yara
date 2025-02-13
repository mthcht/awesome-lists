rule VirTool_Win64_Dumsesesz_A_2147890414_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumsesesz.A!MTB"
        threat_id = "2147890414"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumsesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f8 33 c0 b9 08 02 00 00 f3 aa 33 c9 ff 15 ?? ?? ?? ?? 48 89 44 24 50 48 8d ?? ?? ?? ?? ?? 48 8b 4c 24 50 ff 15 ?? ?? ?? ?? 48 89 44 24 58 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 48 8d ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 44 24 48 48 83}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 44 24 48 48 83 c0 0c 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba ff 01 1f 00 48 8b c8 48 8b 44 24 48 ff ?? ?? ?? ?? ?? 48 89 44 24 58 48 83}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 44 24 48 44 8b 40 08 33 d2 b9 00 00 00 02 48 8b 44 24 48 ff ?? ?? ?? ?? ?? 48 89 44 24 60 48 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

