rule Trojan_Win32_Hideproc_E_2147639707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hideproc.E"
        threat_id = "2147639707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hideproc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NtHideFileMapping" ascii //weight: 1
        $x_1_2 = "HideProcess" ascii //weight: 1
        $x_1_3 = "InstallHook" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = {50 6a 05 e8 6b f9 ff ff a3 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_6 = {0f 94 c2 f6 da 1b d2 85 d2 74 2c 8d 45 ec 50 6a 40 6a 04 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 45 ec 50 6a 04 8d 45 f4 50 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hideproc_F_2147640479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hideproc.F"
        threat_id = "2147640479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hideproc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 89 c7 88 cd 89 c8 c1 e0 10 66 89 c8 89 d1 c1 f9 02 78 09 f3 ab}  //weight: 1, accuracy: High
        $x_1_2 = "NtHideFileMapping" ascii //weight: 1
        $x_1_3 = {6e 74 68 69 64 65 2e 64 6c 6c 00 48 69 64 65 50 72 6f 63 65 73 73 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hideproc_G_2147649497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hideproc.G"
        threat_id = "2147649497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hideproc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 3c 00 61 00 63 00 63 00 65 00 73 00 73 00 2d 00 64 00 65 00 6e 00 69 00 65 00 64 00 3e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c be a2 00 00 00 56 6a 10 5a 8d 4d f0 e8 ?? ?? ?? ?? 81 7d f0 6d d0 4e a2 75 3b 8b 45 f4 39 45 0c 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hideproc_H_2147694021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hideproc.H"
        threat_id = "2147694021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hideproc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "abccba%ddad" wide //weight: 1
        $x_1_2 = {00 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "hideprocess" ascii //weight: 1
        $x_1_4 = {68 6f 6f 6b 5f 70 72 6f 63 65 73 73 [0-16] 73 73 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {73 73 6c 00 3f 75 6e 68 6f 6f 6b 5f 70 72 6f 63 65 73 73}  //weight: 1, accuracy: High
        $x_1_6 = "g_fun_ZwQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

