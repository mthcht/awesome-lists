rule VirTool_Win32_Refledelesz_A_2147910500_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Refledelesz.A!MTB"
        threat_id = "2147910500"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Refledelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 84 24 58 01 00 00 00 00 00 00 50 ?? ?? ?? ?? ?? ?? ?? c7 84 24 74 01 00 00 ?? ?? ?? ?? 50 c7 84 24 7c 01 00 00 ?? ?? ?? ?? c7 84 24 80 01 00 00 ?? ?? ?? ?? 66 c7 84 24 84 01 00 00 ?? 00 c7 84 24 70 01 00 00 ?? ?? ?? ?? 66 c7 84 24 74 01 00 00 ?? 00 c7 44 24 14 [0-16] 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 85 f6 [0-34] 50 6a 40 68 00 10 00 00 56 ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 89 9c 24 68 01 00 00 57 56 53 ?? ?? ?? ?? ?? 8b 73 3c 83 c4 0c 03 f3 89 74 24 0c 6a 40 68 00 30 00 00 ff 76 50 6a 00 ?? ?? ?? ?? ?? ?? ff 76 54 8b f8 53 57}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 84 24 54 01 00 00 00 00 00 00 89 84 24 68 01 00 00 50 ?? ?? ?? ?? ?? ?? ?? 50 ff 74 9c 20 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8b 84 24 68 01 00 00 43 83 c0 06 89 84 24 68 01 00 00 83 fb 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

