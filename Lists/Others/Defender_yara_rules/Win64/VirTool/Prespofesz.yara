rule VirTool_Win64_Prespofesz_A_2147916127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Prespofesz.A!MTB"
        threat_id = "2147916127"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Prespofesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 ce 48 89 f1 [0-17] c1 e8 02 85 c0 89 05 1e aa 11 00 ?? ?? ?? ?? ?? ?? 31 db [0-22] 48 83 c3 01 39 1d f6 a9 11 00 ?? ?? ?? ?? ?? ?? 44 8b 04 9e 45 85 c0 ?? ?? 31 d2 b9 00 00 00 02 ?? ?? 48 85 c0 49 89 c5}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c0 b9 20 00 00 00 31 d2 ?? ?? ?? ?? ?? ?? ?? ?? 41 b9 04 01 00 00 f3 48 ab ?? ?? ?? ?? ?? ?? ?? ?? 4c 89 e9 4d 89 f8 c7 07 00 00 00 00 c6 47 04 00 ?? ?? ?? ?? ?? 85 c0 ?? ?? 4c 89 f9}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 08 00 00 00 48 89 c1 49 89 e8 ?? ?? ?? ?? ?? ?? 45 31 c0 49 89 f1 ba 01 00 00 00 48 89 c1 48 89 84 24 e8 00 00 00 ?? ?? ?? ?? ?? 48 8b 8c 24 e8 00 00 00 31 d2 41 b8 00 00 02 00 48 c7 44 24 30 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 08 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 31 c9 45 31 c0 31 c9 c7 84 24 80 00 00 00 70 00 00 00 4c 89 f2 48 89 7c 24 48 4c 89 7c 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 08 00 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

