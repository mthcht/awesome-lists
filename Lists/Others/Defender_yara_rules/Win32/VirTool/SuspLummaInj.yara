rule VirTool_Win32_SuspLummaInj_B_2147974822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.B"
        threat_id = "2147974822"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 0c 37 83 f8 5c 74 05 83 f8 2f 75 08 c6 44 0c 37 00 49 eb ?? 6a 5c 57 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {f2 0f 10 05 ?? ?? ?? ?? 0f 11 00 0f 57 c0 0f 11 44 24 0c 0f 11 04 24 89 f1 6a 00 6a 14 50 68 03 20 01 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 40 04 01 00 00 00 89 e2 83 22 00 89 f1 52 6a 10 50 68 1f 20 01 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {83 60 04 00 c7 00 59 01 00 00 8d 4c 24 04 83 21 00 6a 00 68 00 00 00 08 6a 40 50 6a 00 6a 0e 51 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspLummaInj_C_2147976849_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.C"
        threat_id = "2147976849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 4d 00 00 00 41 ff d6 41 89 c5 b9 4c 00 00 00 41 ff d6 41 89 c7 b9 4e 00 00 00 41 ff d6 89 c3 b9 4f 00 00 00 41 ff d6 41 89 c6}  //weight: 1, accuracy: High
        $x_1_2 = {41 ff d5 89 c5 b9 f4 01 00 00 41 ff d7 41 ff d5 39 e8 74 ?? 89 c3 31 c9 ff d6 89 dd 85 c0 74 ?? b9 0d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 01 f8 80 38 30 75 ?? 48 8b 44 24 ?? 48 01 f8 80 78 01 78 75 ?? b8 02 00 00 00 48 83 f8 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {31 c9 ff d6 85 c0 74 ?? ff 94 24 ?? ?? ?? ?? b9 0d 00 00 00 4c 89 e2 ff 94 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

