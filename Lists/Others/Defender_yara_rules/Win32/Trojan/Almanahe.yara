rule Trojan_Win32_Almanahe_B_2147595047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.B"
        threat_id = "2147595047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "?action=post&HD=%s&OT" ascii //weight: 2
        $x_1_2 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "%s\\C$\\setup.exe" ascii //weight: 1
        $x_2_4 = "%s?action=update&version=%u" ascii //weight: 2
        $x_1_5 = "htmlfile\\shell\\open\\command" ascii //weight: 1
        $x_2_6 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 2
        $x_2_7 = "ZwLoadDriver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Almanahe_C_2147609322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.C"
        threat_id = "2147609322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 50 89 75 e4 81 7d e4 d0 04 00 00 73 17 8b 45 e4 8d 80 ?? ?? ?? ?? 33 c9 8a 08 83 f1 23 88 08 ff 45 e4 eb e0 56 8d 45 e4 50 68 00 26 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Almanahe_C_2147609322_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.C"
        threat_id = "2147609322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d e4 00 09 00 00 73 17 8b 45 e4 8d 80 ?? ?? ?? ?? 33 c9 8a 08 83 f1 3a 88 08 ff 45 e4 eb e0}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5f 44 4c 5f 43 4f 52 45 34 47 41 45 58 5f 4d 55 54 45 58 5f 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Almanahe_C_2147609322_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.C"
        threat_id = "2147609322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 7c 33 c0 8a 88 ?? ?? ?? ?? 80 f1 66 88 8c 05 fc fe ff ff 40 3d c8 00 00 00 7c e8}  //weight: 5, accuracy: Low
        $x_1_2 = {44 4c 50 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 4c 50 54 65 72 6d 69 6e 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 4c 50 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 5f 44 4c 5f 43 4f 52 45 34 47 41 45 58 5f 4d 55 54 45 58 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 5f 44 4c 34 47 41 45 58 5f 45 58 45 43 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 5f 44 4c 34 47 41 45 58 5f 52 45 53 55 4c 54 5f 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Almanahe_D_2147609346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.D"
        threat_id = "2147609346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 37 33 c0 8a 90 ?? ?? ?? ?? 80 f2 65 88 54 05 a0 40 83 f8 ?? 7c ed}  //weight: 1, accuracy: Low
        $x_1_2 = {41 72 70 50 6c 75 67 69 6e 2e 64 6c 6c 00 44 4c 50 49 6e 69 74 00 44 4c 50 54 65 72 6d 69 6e 61 74 65 00 44 4c 50 55 70 64 61 74 65 00 44 4c 50 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Almanahe_D_2147609346_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.D"
        threat_id = "2147609346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 bd 88 e6 ff ff cc cc cc cc 77 29 81 bd 88 e6 ff ff cc cc cc cc 74 5e 81 bd 88 e6 ff ff aa aa aa aa 74 1f 81 bd 88 e6 ff ff bb bb bb bb 74 32 e9 81 00 00 00 81 bd 88 e6 ff ff dd dd dd dd 74 5c}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 26 48 54 48 3d 25 75 26 48 54 4c 3d 25 75 26 50 54 3d 25 64 26 55 53 3d 25 73 26 50 57 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Almanahe_A_2147645724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Almanahe.A"
        threat_id = "2147645724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 54 24 0c 56 8b 74 24 0c 57 33 ff 85 d2 76 18 8b 44 24 0c 8b ce 2b c6 8b fa 53 8a 1c 08 80 f3 cc 88 19 41 4a 75 f4 5b c6 04 37 00 5f 5e c3}  //weight: 10, accuracy: High
        $x_5_2 = "OpenMutexA" ascii //weight: 5
        $x_5_3 = "__DL5EX__" ascii //weight: 5
        $x_5_4 = "__DL_CORE_MUTEX__" ascii //weight: 5
        $x_5_5 = "ACPI#PNP0D0D#1#Intel_DL5" ascii //weight: 5
        $x_5_6 = "ACPI#PNP0D0D#1#Amd_DL5" ascii //weight: 5
        $x_1_7 = "c_%03d.nls" ascii //weight: 1
        $x_1_8 = "%s\\C$\\Ins.exe" ascii //weight: 1
        $x_1_9 = "htmlfile\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

