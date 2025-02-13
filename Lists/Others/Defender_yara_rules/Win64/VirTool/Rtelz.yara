rule VirTool_Win64_Rtelz_A_2147808496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rtelz.A!MTB"
        threat_id = "2147808496"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rtelz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 81 ec e8 01 00 00 48 8b 35 94 39 12 00 48 89 cb b9 f4 01 00 00 48 8d ?? ?? ?? ff d6 48 8d ?? ?? ?? b9 02 00 00 00 ff 15 ?? ?? ?? ?? 45 31 c9 41 b8 06 00 00 00 ba 01 00 00 00 b9 02 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 03 ff 15 ?? ?? ?? ?? 66 c7 44 24 38 02 00 b9 5c 11 00 00 89 44 24 3c ff 15 ?? ?? ?? ?? 48 8b 2d 4f 3c 12 00 66 89 44 24 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 84 24 18 01 00 00 48 8b 54 24 38 48 3b 50 08 0f 83 ?? ?? ?? ?? 48 89 c1 c7 44 24 60 02 00 00 00 e8 ?? ?? ?? ?? 49 89 c0 48 8b 44 24 38 31 d2 48 8b 4c 24 48 41 b9 01 00 00 00 48 f7 b4 24 e8 00 00 00 48 8b 84 24 e0 00 00 00 66 8b 04 50 66 41 33 00 31 d2 0f b7 c0 4c 8b 84 24 c8 00 00 00 89 44 24 20 e8 ?? ?? ?? ?? 4c 8b 84 24 c8 00 00 00 48 8b 94 24 c0 00 00 00 48 8b 8c 24 10 01 00 00 e8 ?? ?? ?? ?? 48 ff 44 24 38}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 77 65 72 73 68 65 6c 6c [0-32] 2d 63 6f 6d 6d 61 6e 64 [0-32] 28 5b 53 65 63 75 72 69 74 79 2e 50 72 69 6e 63 69 70 61 6c 2e 57 69 6e 64 6f 77 73 50 72 69 6e 63 69 70 61 6c 5d}  //weight: 1, accuracy: Low
        $x_1_4 = "[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]" ascii //weight: 1
        $x_1_5 = {48 8b 84 24 98 01 00 00 48 8d ?? ?? ?? ?? ?? c7 84 24 08 01 00 00 68 00 00 00 c7 84 24 44 01 00 00 00 01 00 00 48 8b 40 18 48 89 84 24 68 01 00 00 48 8b 84 24 98 01 00 00 48 8b 40 08 48 89 54 24 40 4c 89 d2 48 c7 44 24 38 00 00 00 00 48 89 84 24 60 01 00 00 48 8b 84 24 ?? ?? ?? ?? 48 c7 44 24 30 00 00 00 00 48 89 44 24 48 c7 44 24 28 00 00 00 00 c7 44 24 20 01 00 00 00 c7 84 24 80 00 00 00 01 00 00 00 ff 15 ?? ?? ?? ?? 89 44 24 74 48 8b 84 24 ?? ?? ?? ?? ba 10 27 00 00 48 8b 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

