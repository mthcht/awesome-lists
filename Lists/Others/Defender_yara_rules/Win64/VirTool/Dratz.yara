rule VirTool_Win64_Dratz_A_2147844682_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dratz.A!MTB"
        threat_id = "2147844682"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dratz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 32 00 00 00 66 89 85 82 02 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 fa 00 00 00 ff 15 ?? ?? ?? ?? 80 bd 99 08 00 00 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 11 45 c0 4c 89 7d d0 4c 89 7d d8 41 b8 07 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 11 45 c0 4c 89 7d d0 4c 89 7d d8 41 b8 09 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b d0 48 8d ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 0f b6 d8 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

