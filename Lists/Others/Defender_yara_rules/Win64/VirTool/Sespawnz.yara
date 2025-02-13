rule VirTool_Win64_Sespawnz_A_2147849840_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sespawnz.A!MTB"
        threat_id = "2147849840"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sespawnz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f2 48 89 f8 8b 0a 89 08 48 ?? ?? ?? 48 ?? ?? ?? 0f b6 0a 88 08 48 c7 44 24 30 15 01 00 00 48 ?? ?? ?? 48 89 44 24 28 48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8d e0 00 00 00 48 89 4c 24 28 48 8b 8d d8 00 00 00 48 89 4c 24 20 41 b9 00 00 00 00 48 89 c1 48 8b 05 de c8 00 00 ff ?? 89 85 98 00 00 00 83 bd 98 00 00 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

