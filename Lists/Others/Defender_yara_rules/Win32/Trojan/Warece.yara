rule Trojan_Win32_Warece_A_2147599232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Warece.A"
        threat_id = "2147599232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Warece"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 32 33 c0 80 b0 ?? ?? 00 10 ?? 40 3d ?? ?? 00 00 72 f1 6a 01 68 ?? ?? 00 10 e8 ?? ?? ff ff 68 ?? ?? 00 10 50}  //weight: 1, accuracy: Low
        $x_1_2 = {75 d0 8b 46 05 83 c6 05 3b 05 ?? ?? ?? 10 74 6b 3b 05 ?? ?? ?? 10 74 63 6a 01 51 51 8b cc 89 65 ec 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Warece_B_2147610827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Warece.B"
        threat_id = "2147610827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Warece"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 6f 77 66 78 2e 64 6c 6c 00 4d 47 42 00 4d 47 4f}  //weight: 2, accuracy: High
        $x_2_2 = {66 8b 45 0a 66 3b 05 ?? ?? ?? ?? 75 02 b3 01 56}  //weight: 2, accuracy: Low
        $x_1_3 = "--SAVETO" ascii //weight: 1
        $x_1_4 = {50 50 4a 4f 42 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 45 54 54 41 53 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Warece_C_2147611215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Warece.C"
        threat_id = "2147611215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Warece"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 50 68 00 46 00 00 68 00 30 40 00 ff 74 24 20 ff ?? ?? ?? ?? 00 6a 01 53 ff}  //weight: 10, accuracy: Low
        $x_10_2 = "\\\\.\\pipe\\xlibwait" ascii //weight: 10
        $x_10_3 = "\\\\.\\pipe\\mviwait" ascii //weight: 10
        $x_10_4 = "\\\\.\\pipe\\C__WINDOWS_IEXPLORE.EXE" ascii //weight: 10
        $x_10_5 = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders" ascii //weight: 10
        $x_10_6 = "/_ld/?get=file&file=emergency.exe" ascii //weight: 10
        $x_10_7 = "rundll32.exe %11%\\xlibgfl254.dll" ascii //weight: 10
        $x_1_8 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Warece_D_2147615641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Warece.D"
        threat_id = "2147615641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Warece"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 d2 74 08 41 88 10 40 8a 11 eb f4}  //weight: 1, accuracy: High
        $x_1_2 = {c6 00 77 a1 ?? ?? ?? 10 c6 40 08 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {74 1a 8b ce 8a 94 ?? ?? ?? ff ff 3a c2 75 0d 84 d2 74 09 8a 41 01 ?? 41 84 c0 75 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {77 6f 77 66 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

