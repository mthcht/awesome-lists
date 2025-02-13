rule VirTool_Win64_Difrisz_A_2147847728_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Difrisz.A!MTB"
        threat_id = "2147847728"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Difrisz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b e5 41 8b dd 48 89 5d cf 45 8b fd 44 89 6c 24 20 45 33 c9 45 33 c0 33 d2 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b f0 48 89}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 7e 18 48 8b cb 4c ?? ?? ?? 49 03 c6 4c ?? ?? ?? 48 83 fd 08 72 59 48 8b 3e 48 8b d7 e8 ?? ?? ?? ?? 4d 8b c7 49 8b d5 49 8b cc e8 ?? ?? ?? ?? 33 c0 48 8d 14 ?? ?? ?? ?? ?? 66 41 89 06 48 81}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 78 50 48 8b 8d 20 01 00 00 48 8b 95 28 01 00 00 48 8b c2 48 2b c1 48 3b f8 77 35 48 ?? ?? ?? 48 89 85 20 01 00 00 48 8d ?? ?? ?? ?? ?? 48 83 fa 10 48 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

