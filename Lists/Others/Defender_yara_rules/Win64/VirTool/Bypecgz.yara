rule VirTool_Win64_Bypecgz_B_2147912623_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypecgz.B!MTB"
        threat_id = "2147912623"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypecgz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 20 00 00 00 00 41 b9 04 00 00 00 ?? ?? ?? ?? 48 8b 15 9e 6b 11 00 48 8b 0d 77 6b 11 00 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 8b 55 24 [0-19] 48 c7 44 24 20 00 00 00 00 41 b9 04 00 00 00 ?? ?? ?? ?? 48 8b 15 64 6b 11 00 48 8b 0d 3d 6b 11 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 05 ed 66 11 00 89 05 0f 67 11 00 8b 05 e5 66 11 00 89 05 07 67 11 00 8b 05 dd 66 11 00 25 ff 7f 00 00 89 05 fa 66 11 00 48 8b 0d e3 66 11 00 ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 83 3d c7 4f 11 00 00 ?? ?? ?? ?? ?? ?? 48 8b 15 a2 4f 11 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 48 01 00 00 00 b8 0c 00 00 00 48 6b c0 00 48 8b 4d 28 48 89 4c 05 4c b8 0c 00 00 00 48 6b c0 00 c7 44 05 54 02 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 ?? ?? ?? ?? 33 d2 48 8b 8d 50 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 45 08 00 00 00 00 [0-54] ba 20 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 8b d0 [0-18] b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

