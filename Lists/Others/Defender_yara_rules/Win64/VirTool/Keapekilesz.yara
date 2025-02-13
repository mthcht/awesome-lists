rule VirTool_Win64_Keapekilesz_A_2147919487_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Keapekilesz.A!MTB"
        threat_id = "2147919487"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Keapekilesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 81 ec 80 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 c7 85 f8 02 00 00 fe ff ff ff 48 89 8d 88 00 00 00 48 89 8d ?? 00 00 00 48 c7 85 d8 02 00 00 00 00 00 00 48 c7 85 e0 02 00 00 00 00 00 00 48 c7 85 c8 02 00 00 00 00 00 00 48 c7 85 d0 02 00 00 00 00 00 00 31 c0 89 c2 41 b8 02 00 00 00 48 89 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 e0 48 89 45 f8 4c 89 48 38 48 c7 40 60 00 00 00 00 48 c7 40 58 00 00 00 00 48 c7 40 50 00 00 00 00 48 c7 40 48 00 00 00 00 48 c7 40 40 00 00 00 00 c7 40 30 01 00 00 00 c7 40 28 02 00 00 00 c7 40 20 01 00 00 00 41 b9 ff 01 0f 00 ?? ?? ?? ?? ?? 48 89 45 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 a0 48 89 45 f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 4d a0 ?? ?? ?? ?? ?? a8 01 ?? ?? 48 8b 4d a0 48 c7 45 08 00 00 00 00 48 c7 45 10 00 00 00 00 31 d2 31 c0 41 89 c0 ?? ?? ?? ?? ?? 89 45 04 83 f8 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 4d d0 48 89 e0 48 c7 40 30 00 00 00 00 c7 40 28 00 00 00 00 c7 40 20 03 00 00 00 45 31 c0 45 89 c1 ba ff 01 0f 00 ?? ?? ?? ?? ?? 48 89 45 c8 ?? ?? 48 8b 45 c8 48 89 85 88 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 45 e7 a8 01 ?? ?? ?? ?? b1 01 ?? ?? ?? ?? ?? 88 45 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

