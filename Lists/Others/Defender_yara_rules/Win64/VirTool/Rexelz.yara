rule VirTool_Win64_Rexelz_A_2147908297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rexelz.A!MTB"
        threat_id = "2147908297"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rexelz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 11 41 80 0f 10 48 ?? 0f 11 49 ?? 0f 10 40 a0 0f 11 41 a0 0f 10 48 b0 0f 11 49 b0 0f 10 40 c0 0f 11 41 c0 0f 10 48 d0 0f 11 49 d0 0f 10 40 e0 0f 11 41 e0 0f 10 48 f0 0f 11 49 f0 4c 2b ef ?? ?? 0f 10 00 c7 44 24 38 ff ff ff ff 45 33 c9 c7 44 24 30 40 00 00 00 45 33 c0 0f 11 01 8b 40 10 49 8b d6 89 41 10 48 8b cb 44 89 7c 24 28 4c 89 7c 24 20 ?? ?? ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 78 18 00 00 ?? ?? ?? ?? ?? 48 2b e0 48 8b 05 e9 3f 00 00 48 33 c4 48 89 85 50 17 00 00 ?? ?? ?? ?? ?? ?? b9 88 13 00 00 [0-18] 8b 14 25 04 00 fe 7f 4c 8b c0 8b 0c 25 20 03 fe 7f 8b fa 48 0f af f9 8b 0c 25 24 03 fe 7f c1 e1 08 0f af ca 48 c1 ef 18}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 00 10 00 00 [0-18] 8b 85 a0 01 00 00 83 e0 fc 83 f8 50 [0-25] 83 bd c8 01 00 00 02}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 85 e0 11 00 00 41 64 76 61 c7 85 e4 11 00 00 70 69 33 32 40 88 bd e8 11 00 00 f3 0f 7f 85 20 13 00 00 66 c7 85 30 13 00 00 32 00 ?? ?? ?? ?? ?? ?? 48 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

