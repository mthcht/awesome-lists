rule VirTool_Win64_Ghesesz_A_2147890415_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ghesesz.A!MTB"
        threat_id = "2147890415"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ghesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 4c 8d 8c ?? ?? ?? ?? ?? 45 33 c0 48 ?? ?? ?? ?? 48 8b 4c 24 58 48 8b 84 24 00 01 00 00 ff ?? ?? ?? ?? ?? 48 83}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 58 c7 40 08 03 01 00 00 41 b9 18 00 00 00 4c 8d 84 ?? ?? ?? ?? ?? ba 07 00 00 00 48 c7 c1 fe ff ff ff 48 8b 84 24 40 01 00 00 ff ?? ?? ?? ?? ?? 89 44 24 50 83 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b f8 33 c0 b9 08 02 00 00 f3 aa 33 c9 ff 15 ?? ?? ?? ?? 48 89 44 24 50 48 8d ?? ?? ?? ?? ?? 48 8b 4c 24 50 ff 15 ?? ?? ?? ?? 48 89 44 24 58 48 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 48 8d ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 44 24 48 48 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

