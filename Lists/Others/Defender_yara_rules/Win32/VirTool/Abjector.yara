rule VirTool_Win32_Abjector_A_2147782215_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Abjector.A!MTB"
        threat_id = "2147782215"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Abjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cc 55 8b ec [0-8] 64 [0-2] 30 00 00 00 [0-14] 8b ?? 0c 83 ?? 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 c0 07 8d 52 01 0f be c9 33 c1 8a 0a 84 c9}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 30 00 00 [0-7] ff ?? 50 [0-8] 6a 00 89 45 ?? ff}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 4d 5a 00 00 66 39}  //weight: 1, accuracy: High
        $x_1_5 = {6a 01 6a 01 ?? 03 ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Abjector_C_2147783672_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Abjector.C!MTB"
        threat_id = "2147783672"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Abjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 51 8d 85 ?? ?? ?? ?? [0-7] 50 51 [0-3] c7 85 00 01 00 00 00 ff 15 [0-41] 6a 00 b8 00 00 10 00 8d 0c 37 2b c7 50 51 [0-3] ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3c 37 20 74 ?? 56 47 ff [0-5] 3b f8 7c [0-27] 20 [0-2] e8 [0-6] 83 f8 01 7e 08 8d 46 01 03 c7 89 45 ?? c6 04 37 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 [0-7] 8d 45 ?? 89 75 ?? 50 6a 04 8d 45 e8 50 [0-2] 6a ?? ff 75 fc ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

