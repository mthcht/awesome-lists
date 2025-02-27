rule VirTool_Win64_Venomesz_A_2147902288_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Venomesz.A!MTB"
        threat_id = "2147902288"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Venomesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 20 00 00 00 30 45 33 c9 45 33 c0 ?? ?? ?? ?? 33 c9 ?? ?? ?? ?? ?? ?? 48 8b f8 41 b8 bb 01 00 00 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ?? ?? 48 8b f0 c7 44 24 30 00 00 80 00 4c 89 7c 24 28 4c 89 7c 24 20 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 05 e5 4b 00 00 4c 89 6c 24 68 4c 89 6d 28 ?? ?? ?? ?? ?? ?? 48 8b d0 c7 44 24 48 40 00 00 00 4c 89 6c 24 40 c7 44 24 38 01 00 00 00 ?? ?? ?? ?? 48 89 44 24 30 4c 89 6c 24 28 4c 89 6c 24 20 45 33 c9 ?? ?? ?? ?? ?? 48 8b 4c 24 78 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 6d 80 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 44 24 48 40 00 00 00 4c 89 6c 24 40 c7 44 24 38 01 00 00 00 ?? ?? ?? ?? 48 89 44 24 30 4c 89 6c 24 28 4c 89 6c 24 20 45 33 c9 ?? ?? ?? ?? 48 8b 54 24 58 48 8b 4c 24 78 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

