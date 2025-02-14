rule VirTool_Win64_Steflesz_A_2147924243_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Steflesz.A!MTB"
        threat_id = "2147924243"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Steflesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 8b 45 ec 41 89 c0 ba 00 00 00 00 b9 ff 03 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 e0 83 7d f4 0d ?? ?? 8b 45 f4 89 05 e7 37 00 00 48 8b 45 e0 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 05 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 e0 48 89 c1 [0-22] 48 8b 00 48 8b 4d 20 48 8b 55 18 49 89 c9 49 89 d0 8b 55 10 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {55 53 48 83 ec 58 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 4d f0 41 b9 00 00 00 00 41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? b9 0d 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 10 ?? ?? ?? ?? ?? ?? ?? 48 8b 00 48 85 c0 [0-17] 89 c3 b9 02 00 00 00 48 8b 05 96 37 00 00 ?? ?? 41 89 d9}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 f8 8b 45 f8 41 89 c0 ba 00 00 00 00 b9 ff 03 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f0 ?? ?? ?? ?? 41 b8 30 00 00 00 48 89 c2 48 8b 4d 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? b9 e8 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 55 d8 48 8b 45 c0 ?? ?? ?? ?? ?? ?? ?? 49 89 c9 41 b8 01 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 18 14 00 00 48 89 85 50 18 00 00 ?? ?? ?? ?? 48 8b 95 50 18 00 00 48 8b 8d 60 18 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 41 b9 08 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 85 18 14 00 00 48 05 08 01 00 00 48 89 85 18 14 00 00 48 8b 85 a0 12 00 00 48 2d 08 01 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? 48 8b 85 60 18 00 00 48 c7 44 24 20 00 00 00 00 41 b9 08 01 00 00 49 89 d0 48 89 ca 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

