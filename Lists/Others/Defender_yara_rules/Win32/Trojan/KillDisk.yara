rule Trojan_Win32_KillDisk_H_2147619520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.H"
        threat_id = "2147619520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 00 42 41 54 ?? ?? ?? ?? 40 65 63 68 6f 20 6f 66 66 [0-8] 64 65 6c 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 [0-16] 73 68 75 74 64 6f 77 6e 20 2d 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillDisk_K_2147628323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.K"
        threat_id = "2147628323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 18 00 09 00 56 ff d3 8d 44 24 10 6a 00 50 8d 4c 24 20 6a 18 51 6a 00 6a 00 68 00 00 07 00 56 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0c 38 80 f1 ?? 88 0c 38 40 3d fe 01 00 00 7c ef}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 02 00 00 57 56 ff 15 ?? ?? ?? ?? 85 c0 74 5a 81 7c 24 14 00 02 00 00 72 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillDisk_L_2147641609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.L"
        threat_id = "2147641609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\\\.\\PHYSICALDRIVE0" ascii //weight: 2
        $x_1_2 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_3 = {45 52 52 4f 52 20 52 45 42 4f 4f 54 00}  //weight: 1, accuracy: High
        $x_3_4 = {8d 15 1b 30 40 00 6a 00 51 68 00 ?? 00 00 52 53 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillDisk_N_2147718941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.N!dha"
        threat_id = "2147718941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shutdown /r /t %d" ascii //weight: 1
        $x_1_2 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_3 = "/c sc create" ascii //weight: 1
        $x_2_4 = "\"cmd /c del %s\"" ascii //weight: 2
        $x_2_5 = "/c format %c: /Y /X /FS:NTFS" ascii //weight: 2
        $x_10_6 = "vssadmin delete shadows /all /quiet" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillDisk_YA_2147731869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.YA!MTB"
        threat_id = "2147731869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 7
        $x_7_2 = "taskkill.exe /f /im" wide //weight: 7
        $x_1_3 = "PowerShell Set-MpPreference -DisableRealtimeMonitoring 1" wide //weight: 1
        $x_1_4 = "DisableAntiSpyware" wide //weight: 1
        $x_1_5 = "DisableBehaviorMonitoring" wide //weight: 1
        $x_1_6 = "DisableOnAccessProtection" wide //weight: 1
        $x_1_7 = "DisableScanOnRealtimeEnable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_7_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillDisk_ARA_2147925942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.ARA!MTB"
        threat_id = "2147925942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\SHOTHIRIUM.pdb" ascii //weight: 2
        $x_2_2 = "\\\\.\\PhysicalDrive0" wide //weight: 2
        $x_2_3 = "Run malware" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillDisk_EAEB_2147936234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.EAEB!MTB"
        threat_id = "2147936234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b ca c1 e9 10 d3 ea 8b 8d dc ac f8 ff 8b c1 c1 e8 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillDisk_EEB_2147941313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillDisk.EEB!MTB"
        threat_id = "2147941313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 d0 88 94 05 ?? ?? ?? ?? 40 3d 80 a9 03 00 72 ?? ?? ?? ?? ?? ?? ?? c7 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

