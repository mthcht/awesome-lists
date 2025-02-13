rule VirTool_Win32_Joiner_A_2147603252_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Joiner.gen!A"
        threat_id = "2147603252"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Joiner"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 48 6a 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ad 00 00 00 8b db 8a ed 8b c0 ?? 6a 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 95 00 00 00 eb 05 6f 70 65 6e 00 ff 35 ?? ?? ?? ?? e8 59 00 00 00 8b db 8a ed 8b c0 ?? 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 71 00 00 00 e9 5d fd ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c2 05 01 00 00 8b db 8a ed 8b c0 ?? f7 da 6a 02 6a 00 52 ff 35 ?? ?? ?? ?? e8 d7 02 00 00 6a 00 68 ?? ?? ?? ?? 68 00 01 00 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 b5 02 00 00 6a 00 68 ?? ?? ?? ?? 6a 04 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 9c 02 00 00 83 3d ?? ?? ?? ?? ff 0f 84 3b 02 00 00 83 3d ?? ?? ?? ?? 00 0f 84 2e 02 00 00 ?? 8b 1d ?? ?? ?? ?? 01 1d ?? ?? ?? ?? 8b db 8a ed 8b c0 ?? 81 05 ?? ?? ?? ?? 05 01 00 00 f7 1d ?? ?? ?? ?? 6a 02 6a 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 4f 02 00 00 f7 1d ?? ?? ?? ?? ?? 8a ed 8b c0 68 ?? ?? ?? ?? 68 00 01 00 00 e8 29 02 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {75 73 65 72 33 32 2e 64 6c 6c 00 ?? ?? ?? 43 6c 6f 73 65 48 61 6e 64 6c 65 00 ?? ?? 43 72 65 61 74 65 46 69 6c 65 41 00 ?? ?? 45 78 69 74 50 72 6f 63 65 73 73 00 ?? ?? 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 00 ?? ?? ?? 47 65 74 54 65 6d 70 50 61 74 68 41 00 ?? ?? ?? 52 65 61 64 46 69 6c 65 00 ?? ?? ?? 53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 00 ?? ?? ?? 57 72 69 74 65 46 69 6c 65 00 ?? ?? 6c 73 74 72 63 61 74 41 00 ?? 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 ?? ?? ?? 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 53 48 45 4c 4c 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Joiner_B_2147606762_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Joiner.gen!B"
        threat_id = "2147606762"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Joiner"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Result.exe = %lu" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "Icon, Exe, DLL (*.ico, *.exe, *.dll)" ascii //weight: 1
        $x_1_4 = {e8 61 00 00 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 01 ff ?? ?? ?? ?? ?? e8 b1 00 00 00 8a c0 66 8b db 8a ed 6a 00 e8 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Joiner_E_2147623751_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Joiner.E"
        threat_id = "2147623751"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Joiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 00 00 00 00 bb 00 04 00 00 f7 f3 a3 ?? ?? 40 00 89 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 04 00 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 e8 ?? ?? 00 00 6a 00 68 ?? ?? 40 00 68 00 04 00 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {57 72 69 74 65 46 69 6c 65 00 b5 02 6c 73 74 72 63 61 74 41 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 06 01 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 53 48 45 4c 4c 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

