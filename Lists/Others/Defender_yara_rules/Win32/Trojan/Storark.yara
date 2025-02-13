rule Trojan_Win32_Storark_A_2147599277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storark.A"
        threat_id = "2147599277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 02 00 00 00 eb 3e 8a 44 1c 20 88 04 24 8a 44 1c 21 88 44 24 01 c6 44 24 02 00 8b c4 e8 ?? ?? ff ff 8b d7 81 f2 9e 00 00 00 33 c2 88 04 24 c6 44 24 01 00 54 8d 84 24 24 04 00 00 50 e8 ?? ?? ff ff 83 c3 02 8b c6 83 e8 02 3b d8 7e b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Storark_B_2147600460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storark.B"
        threat_id = "2147600460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 02 00 00 00 eb 42 8a 44 1c 24 88 44 24 04 8a 44 1c 25 88 44 24 05 c6 44 24 06 00 8d 44 24 04 e8 ?? ?? ff ff 8b d5 33 d7 33 c2 88 44 24 04 c6 44 24 05 00 8d 44 24 04 50 8d 84 24 28 04 00 00 50 e8 ?? ?? ff ff 83 c3 02 8b c6 83 e8 02 3b d8 7e b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Storark_D_2147604997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storark.D"
        threat_id = "2147604997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 4c 6f 6f 70 0d 0a 61 74 74 72 69 62 20 22 00 00 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68 0d 0a 64 65 6c 20 22 00 00 00 00 22 0d 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 64 65 6c 20 25 30}  //weight: 10, accuracy: High
        $x_5_2 = "verclsid.exe" ascii //weight: 5
        $x_3_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\ShellExecuteHooks" ascii //weight: 3
        $x_3_4 = "AppInit_DLLs" ascii //weight: 3
        $x_2_5 = "NoAutoUpdate" ascii //weight: 2
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Storark_C_2147605000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storark.C"
        threat_id = "2147605000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 74 74 72 69 62 20 22 00 00 00 00 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68}  //weight: 1, accuracy: High
        $x_1_2 = {69 66 20 65 78 69 73 74 20 22 00 00 00 22 20 67 6f 74 6f 20}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 6c 20 22 00 00 00 00 22}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 00 00 00 00 41 70 70 49 6e 69 74 5f 44 4c 4c 73}  //weight: 1, accuracy: High
        $x_1_5 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 5c 41 55 00 00 00 00 4e 6f 41 75 74 6f 55 70 64 61 74 65 00 00 00 00 41 55 4f 70 74 69 6f 6e 73}  //weight: 1, accuracy: High
        $x_1_6 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 00 00 00 00 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Storark_A_2147607384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storark.gen!A"
        threat_id = "2147607384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storark"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 3c 01 0f 85 ?? 00 00 00 68 ?? ?? 40 00 8d 84 24 ?? ?? 00 00 50 e8 ?? ?? ff ff 56 8d 84 24 ?? ?? 00 00 50 e8}  //weight: 5, accuracy: Low
        $x_1_2 = {00 4e 6f 41 75 74 6f 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4e 55 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 3f 61 3d 00 [0-4] 26 62 3d 00 26 63 3d 00 26 64 3d 00 26 65 3d 00 26 66 3d 00 26 67 3d 00 26 68 3d 00 26 69 3d 00 [0-4] 26 6a 3d 00 26 6b 3d 00 26 6c 3d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 4c 6f 6f 70 0d 0a 61 74 74 72 69 62 20 22 00 00 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68 0d 0a 64 65 6c 20 22 00 00 00 00 22 0d 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 64 65 6c 20 25 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

