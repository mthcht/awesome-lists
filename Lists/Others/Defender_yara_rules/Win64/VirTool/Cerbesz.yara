rule VirTool_Win64_Cerbesz_A_2147963244_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cerbesz.A"
        threat_id = "2147963244"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 57 c0 0f 11 44 24 20 48 c7 44 24 30 00 00 00 00 48 89 c1 89 da 49 89 f8 41 b9 02 00 00 00 48 89 c3 e8 ?? ?? ?? ?? 89 c5 48 89 d9 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b b4 24 88 00 00 00 48 89 f1 e8 ?? ?? ?? ?? 48 c7 44 24 48 00 00 00 00 48 8b 7c 24 70 ?? ?? ?? ?? ?? 48 89 44 24 20 48 c7 c1 02 00 00 80 48 89 fa 45 31 c0 41 b9 19 00 02 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 7c 24 50 48 c7 44 24 58 00 00 00 00 ?? ?? ?? ?? ?? 48 89 44 24 28 c7 44 24 20 01 00 00 00 4c 89 f9 ba ff 01 0f 00 45 31 c0 41 b9 02 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

