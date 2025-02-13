rule VirTool_Win64_Novelodesz_A_2147895155_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Novelodesz.A!MTB"
        threat_id = "2147895155"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Novelodesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c6 0f 28 05 eb 61 02 00 0f 11 00 48 b8 41 50 41 51 41 52 41 53 48 89 46 10 66 c7 46 18 48 b9 48 83 66 1a 00 66 c7 46 22 48 ba 48 83 66 24 00 48 b8 48 89 08 48 89 50 08 48 48 89 46 2c c6 46 34 b8 48 83 66 35 00 48 b8 ff d0 41 5b 41 5a}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 02 00 00 00 48 89 e9 e8 ?? ?? ?? ?? 48 89 e9 e8 ?? ?? ?? ?? b9 20 00 00 00 e8 ?? ?? ?? ?? 48 89 c7 48 b8 55 48 89 e5 48 83 ec 30 48 89 07 66 c7 47 08 48 b9 48 83 67 0a 00 66 c7 47 12 48 b8 48 83 67 14 00 c7 47}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 84 24 88 01 00 00 48 89 84 24 70 01 00 00 48 8b 45 00 48 89 84 24 80 00 00 00 b9 4b 00 00 00 e8 ?? ?? ?? ?? 48 89 c6 0f 28 05 eb 61 02 00 0f 11 00 48 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

