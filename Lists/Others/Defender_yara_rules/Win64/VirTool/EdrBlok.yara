rule VirTool_Win64_EdrBlok_D_2147926827_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/EdrBlok.D"
        threat_id = "2147926827"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EdrBlok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 50 45 31 c9 45 31 c0 ba ff ff ff ff ?? ?? ?? ?? ?? 48 89 cb 31 c9 48 c7 44 24 38}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 20 41 b9 00 00 00 00 41 b8 00 00 00 00 ba ff ff ff ff b9}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 da 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 48 89 da e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 45 f0 48 8b 55 10 48 89 c1 e8 ?? ?? ?? ?? 89 45 fc 48 8b 05 3d 20 01 00 48 8d 55 e0 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 4c 24 38 e8 ?? ?? ?? ?? ?? 48 83 c4 50 5b c3 66 2e 0f 1f 84}  //weight: 1, accuracy: Low
        $x_1_6 = {48 8b 45 f0 ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_7 = {48 89 df f3 48 ab ?? ?? ?? ?? ?? 48 89 44 24 20}  //weight: 1, accuracy: Low
        $x_1_8 = {89 85 2c 03 00 00 83 bd 2c 03 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 85 50 03 00 00 41 b8 04 01 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_9 = {48 8b 4c 24 38 45 31 c0 f3 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? c7 84 24 b0}  //weight: 1, accuracy: Low
        $x_1_10 = {48 8b 05 4a 23 01 00 48 89 45 e0 48 ?? ?? ?? ?? ?? ?? 48 89 45 e8 c7 45 f0 01 00 00 00 48 8b 85 18 03 00 00 ?? ?? ?? ?? 41 b8 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

