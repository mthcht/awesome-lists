rule VirTool_Win64_Dumphash_A_2147912786_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumphash.A!MTB"
        threat_id = "2147912786"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumphash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba ff 01 0f 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 8b d0 [0-18] b8 01 00 00 00 [0-16] 33 c9 [0-19] 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 8b d0 [0-18] b8 01 00 00 00 ?? ?? ?? ?? ?? 48 8b 4c 24 48 ?? ?? ?? ?? ?? 4c 89 74 24 28 41 b9 10 00 00 00 33 d2 4c 89 74 24 20 c7 44 24 58 01 00 00 00 c7 44 24 64 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 01 00 00 00 [0-18] b9 01 00 00 00 [0-19] 44 8b c3 33 d2 b9 10 10 00 00 ?? ?? ?? ?? ?? ?? 48 8b f8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 ac 24 f0 04 00 00 ?? ?? ?? ?? ?? ?? ?? ?? c7 44 24 50 04 01 00 00 33 d2 48 8b cf ?? ?? ?? ?? ?? ?? 45 33 c9 4c 89 74 24 30 44 89 74 24 28 ?? ?? ?? ?? ?? ?? ?? ?? ba 00 00 00 80 c7 44 24 20 03 00 00 00 [0-16] 48 8b e8 48 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 89 74 24 30 41 b9 02 00 00 00 4c 89 74 24 28 4c 8b c6 8b d3 4c 89 74 24 20 48 8b cf ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

