rule VirTool_Win32_Blemesez_A_2147902287_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Blemesez.A!MTB"
        threat_id = "2147902287"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Blemesez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 3c 02 00 00 c7 85 60 ff ff ff 46 61 69 6c c7 85 64 ff ff ff 65 64 20 74 c7 85 68 ff ff ff 6f 20 63 72 c7 85 6c ff ff ff 65 61 74 65 c7 85 70 ff ff ff 20 50 65 72 c7 85 74 ff ff ff 73 69 73 74 c7 85 78 ff ff ff 65 6e 63 65 c7 85 7c ff ff ff 2e 0a 00 00 ?? ?? ?? b8 00 00 00 00 b9 18 00 00 00 89 d7 f3 ab ?? ?? ?? ?? ?? ?? ba ?? ?? ?? ?? b9 1b}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 e0 8b 85 d8 fd ff ff 8b 55 e0 89 54 24 14 ?? ?? ?? ?? ?? ?? 89 54 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 1e d1 40 00 89 04 24 ?? ?? ?? ?? ?? 83 ec 18 85 c0 ?? ?? 8b 85 d8 fd ff ff 89 04 24 ?? ?? ?? ?? ?? 83 ec 04}  //weight: 1, accuracy: Low
        $x_1_3 = {89 44 24 04 c7 04 24 56 d2 40 00 ?? ?? ?? ?? ?? 85 c0 ?? ?? c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 f3 15 40 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ?? ?? ?? ?? ?? 83 ec 18 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

