rule VirTool_Win64_Secdump_A_2147910498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Secdump.A!MTB"
        threat_id = "2147910498"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Secdump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 41 8b de 48 89 44 24 50 4c 89 74 24 58 4c 89 74 24 60 [0-17] ba 08 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 4c 24 60 ?? ?? ?? ?? ?? 41 b9 04 00 00 00 44 89 74 24 68 ?? ?? ?? ?? ?? c7 44 24 40 04 00 00 00 48 89 44 24 20}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 28 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 0d 8b 1e 00 00 [0-25] 33 c9 [0-19] 85 c0 [0-17] 48 8b 44 24 60 ?? ?? ?? ?? ?? 48 8b 4c 24 40 41 b9 10 00 00 00 4c 89 74 24 28 33 d2 48 89 44 24 74 c7 44 24 70 01 00 00 00 c7 44 24 7c 02 00 00 00 4c 89 74 24 20 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 20 02 00 00 00 ba 00 00 00 40 [0-17] 48 c7 44 24 60 05 00 00 00 48 8b f8 ?? ?? ?? ?? ?? 48 8b 4c 24 48 ?? ?? ?? ?? ?? ?? 48 8b 4c 24 48 41 b9 02 00 00 00 4c 89 74 24 30 8b d0 4c 89 74 24 28 4c 8b c7 4c 89 74 24 20}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 10 04 00 00 [0-20] 85 c0 [0-33] ba 04 01 00 00 [0-18] 4c 89 74 24 30 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 45 33 c9 45 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

