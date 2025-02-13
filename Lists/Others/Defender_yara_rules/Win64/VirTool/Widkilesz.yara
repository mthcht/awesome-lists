rule VirTool_Win64_Widkilesz_A_2147852614_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Widkilesz.A!MTB"
        threat_id = "2147852614"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Widkilesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 5c 01 00 00 00 e8 ?? ?? ?? ?? 84 c0 0f 84 aa 01 00 00 48 ?? ?? ?? ?? 45 31 c0 41 b9 3f 00 0f 00 48 c7 c1 02 00 00 80 48 89 44 24 20 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 60 45 31 c0 c7 44 24 28 04 00 00 00 41 b9 04 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 74 24 20 ff ?? 31 c0 31 d2 31 c9 48}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 54 24 78 4c ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 4c 24 78 85 c0 74 1d ff 15 ?? ?? ?? ?? 8b 44 24 6c 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

