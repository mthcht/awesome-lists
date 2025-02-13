rule VirTool_Win64_Earlebedesz_A_2147912624_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Earlebedesz.A!MTB"
        threat_id = "2147912624"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Earlebedesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 bc 24 10 02 00 00 33 c9 48 89 7d 28 0f 11 45 68 ?? ?? ?? 48 89 85 c8 00 00 00 0f 11 45 78 48 89 7d 20 0f 11 85 88 00 00 00 0f 11 85 98 00 00 00 0f 11 85 a8 00 00 00 0f 11 85 b8 00 00 00 [0-18] 4c 8b 45 30 33 d2 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 60 70 00 00 00 48 89 44 24 48 [0-17] 45 33 c9 48 89 44 24 40 45 33 c0 48 89 7c 24 38 33 c9 48 89 7c 24 30 c7 44 24 28 04 00 08 00 c7 44 24 20 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 55 40 45 33 c0 48 8b 4d 20 ?? ?? 4c 8b b4 24 18 02 00 00 48 8b bc 24 48 02 00 00 48 8b b4 24 40 02 00 00 48 8b 9c 24 30 02 00 00 85 c0 [0-20] 4c 8b 45 20 [0-25] 48 8b 4d 40}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8b 0d ff 13 02 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 55 20 48 8b 4d 38 48 89 7c 24 20 ?? ?? 48 8b 55 20 ?? ?? ?? ?? ?? ?? ?? 89 05 14 26 02 00 ?? ?? ?? ?? ?? 39 3d 09 26 02 00}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 4d 38 ?? ?? ?? ?? ?? ?? ?? 41 b9 20 00 00 00 48 89 44 24 20 ?? ?? ?? ?? ?? ?? ?? 89 bd d0 00 00 00 ?? ?? ?? ?? ?? ?? 4c 8b bc 24 10 02 00 00 89 05 cb 24 02 00 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

