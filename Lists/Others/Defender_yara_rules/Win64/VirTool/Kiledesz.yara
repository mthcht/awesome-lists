rule VirTool_Win64_Kiledesz_A_2147982773_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kiledesz.A"
        threat_id = "2147982773"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kiledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 6c 24 58 41 b9 ff 01 0f 00 4c 89 6c 24 50 48 8b cf 4c 89 6c 24 48 4c 89 6c 24 40 4c 89 74 24 38 44 89 6c 24 30 c7 44 24 28 03 00 00 00 c7 44 24 20 01 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {45 33 c0 33 d2 48 8b ce ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 08 00 00 00 41 b9 08 00 00 00 48 89 44 24 20 ba 44 20 22 00 48 89 bd d8 03 00 00 48 8b ce 89 7c 24 40 c7 85 d0 03 00 00 08 00 00 00 89 9d d4 03 00 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

