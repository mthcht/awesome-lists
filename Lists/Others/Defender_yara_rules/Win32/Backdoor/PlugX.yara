rule Backdoor_Win32_PlugX_B_2147913403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PlugX.B!dha"
        threat_id = "2147913403"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 f2 ae f7 d1 49 51 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 33 c0 b9 19 00 00 00 8d 7c ?? ?? 50 50 50 50 f3 ab 68 ?? ?? ?? ?? c7 44 ?? ?? 00 00 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = "cmd /c \"ping 1&del /Q \"%s*.*" ascii //weight: 1
        $x_1_3 = "slides.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PlugX_B_2147913404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PlugX.B.dll!dha"
        threat_id = "2147913404"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 fb e6 21 00 00 77 ?? 85 db 0f 84 ?? ?? ?? ?? 80 34 30 03 40 3b c3 72 ?? e9 ?? ?? ?? ?? 81 fb 16 31 01 00 0f 82 ?? ?? ?? ?? 80 34 30 03 40 3d e6 21 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 69 63 72 66 2e 72 61 74 [0-4] 54 00 50 00 41 00 75 00 74 00 6f 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 79 4d 69 6e 69 48 4e 53 65 6c 66 44 65 6c 65 74 65 64 53 74 75 62 44 6c 6c [0-4] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PlugX_C_2147913405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PlugX.C"
        threat_id = "2147913405"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 12 68 28 20 00 10 8d 85 fc f7 ff ff 50 ff 15 08 20 00 10 53 56 57 6a 40}  //weight: 1, accuracy: High
        $x_1_2 = {6b c0 64 03 c1 3d 2e 2b 33 01 0f 82 99 00 00 00 56 6a 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 c0 33 c1 a3 08 30 00 10 c6 06 e9 81 35 08 30 00 10 e9 00 00 00 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

