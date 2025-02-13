rule VirTool_Win32_Filnesez_A_2147891647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Filnesez.A!MTB"
        threat_id = "2147891647"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Filnesez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 85 f6 ?? ?? 68 00 00 06 00 6a 00 6a 00 68 44 c6 43 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 2f 8b d7 8b ce e8 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fc 01 8b cf e8 ?? ?? ?? ?? 83 c4 18 8b f0 ba a4 cc 43 00 b9 70 42 44 00 e8 ?? ?? ?? ?? 57 8b c8 e8 24}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 fc 00 e8 ?? ?? ?? ?? 83 c4 18 8b c8 e8 ?? ?? ?? ?? 56 6a 00 6a 00 6a ff 6a 00 89 46 04 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 68 a4 d9 43 00 68 b4 d9 43 00 ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 45 fc 08 ba c0 cc 43 00 b9 70 42 44 00 e8 ?? ?? ?? ?? 8d ?? ?? 8b c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ?? 8d ?? ?? 8d ?? ?? e8 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

