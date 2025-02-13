rule Trojan_Win32_Pernefed_133372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = {50 44 32 30 ?? ?? 4d 6f 6e 69 74 6f 72 00 00 00 70 64 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\WINDOWS\\pd.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pernefed_133372_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 03 2f c6 43 01 71 c6 43 02 0d c6 43 03 0a c6 43 04 69 c6 43 05 66 c6 43 06 20 c6 43 07 65 c6 43 08 78}  //weight: 2, accuracy: High
        $x_2_2 = {8a 54 3a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 f8 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0}  //weight: 2, accuracy: Low
        $x_1_3 = {72 75 6e 6d 61 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 75 6e 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 44 00 32 00 30 00 ?? ?? ?? ?? 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pernefed_133372_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {55 8b ec 83 c4 f0 b8 ?? ?? 50 00 e8 ?? ?? ef ff 68 ?? ?? 50 00 e8 ?? ?? ef ff 8b 15 ?? ?? 51 00 89 02 68 ?? ?? 50 00 6a 00 6a 00 e8 ?? ?? ef ff 85 c0 79 05}  //weight: 100, accuracy: Low
        $x_1_2 = {ff ff ff ff 10 00 00 00 46 6f 75 6e 64 20 74 68 72 65 61 74 73 3a 20 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff ff 15 00 00 00 53 74 61 74 75 73 3a 20 53 63 61 6e 6e 69 6e 67 20 66 69 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pernefed_133372_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = "SOFTWARE\\Microsoft\\PDefender" ascii //weight: 1
        $x_1_3 = "Perfect Defender" ascii //weight: 1
        $x_1_4 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pernefed_133372_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 3a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 f8 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 0a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? ff 45 ?? ff 4d ?? 75 d5}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 54 38 ff 8a 04 1e e8 ?? ?? ?? ?? 88 04 1e 8b 45 fc 8a 44 38 ff 30 04 1e 43 ff 4d ?? 75 de}  //weight: 1, accuracy: Low
        $x_1_4 = {8f 9b 99 91 9b 8d 00}  //weight: 1, accuracy: High
        $x_1_5 = {8f 9b 92 90 91 96 8b 90 8d 00}  //weight: 1, accuracy: High
        $x_1_6 = {bb 9a 99 9a 91 9b 9a 8d}  //weight: 1, accuracy: High
        $x_1_7 = {cc e0 db ff ff ff dd eb e6 78 ad 9f 02 63 4e 02 6e 3d 02 7c 26 24 8e 42 ff ff ff ff ff ff 24 76}  //weight: 1, accuracy: High
        $x_2_8 = {2d 16 01 00 00 48 50 8b 45 ?? 2d 5e 01 00 00 11 00 6a 00 6a 30 e8 ?? ?? ?? ?? 68 00 00 40 00 8b 45 ??}  //weight: 2, accuracy: Low
        $x_2_9 = {8a 45 08 2c 01 72 77 0f 84 99 00 00 00 fe c8 74 09 fe c8 74 39 e9 b2 00 00 00 ba}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pernefed_133372_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 44 65 6c 65 74 65 20 2f 2f 54 4e 20 22 44 65 66 65 6e 64 65 72 20 4d 6f 6e 69 74 6f 72 22}  //weight: 2, accuracy: Low
        $x_1_2 = {59 6f 75 20 61 72 65 20 6e 6f 77 20 72 65 61 64 79 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 74 68 65 20 50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 20 32 30 ?? ?? 20 66 72 6f 6d 20 79 6f 75 72 20 73 79 73 74 65 6d 2e}  //weight: 1, accuracy: Low
        $x_2_3 = {64 65 6c 65 74 65 64 2e 2e 2e 00 [0-12] 63 61 6e 27 74 20 64 65 6c 65 74 65 20 50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 20 32 30 ?? ?? 20 6b 65 79 73 2e 2e 2e}  //weight: 2, accuracy: Low
        $x_1_4 = "Uninstall\\PDefender" ascii //weight: 1
        $x_1_5 = "Microsoft\\PDefender" ascii //weight: 1
        $x_1_6 = {20 74 6f 20 63 6f 6d 70 6c 65 74 65 6c 79 20 72 65 6d 6f 76 65 20 50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 2e 00 [0-8] 5c 70 64 6d 6f 6e 69 74 6f 72 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pernefed_133372_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pernefed"
        threat_id = "133372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pernefed"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 3a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 f8 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0}  //weight: 2, accuracy: Low
        $x_2_2 = "Schtasks.exe /create /tn \"Defender Monitor\"" ascii //weight: 2
        $x_1_3 = {2f 75 70 64 61 74 65 2e 70 68 70 3f 62 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "After your computer started up, run Instalation again." ascii //weight: 1
        $x_1_5 = "Perfect Defender 200" ascii //weight: 1
        $x_2_6 = {8a 54 0a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? ff 45 ?? ff 4d ?? 75}  //weight: 2, accuracy: Low
        $x_2_7 = {50 44 32 30 30 39 53 68 75 74 74 69 6e 67 00}  //weight: 2, accuracy: High
        $x_1_8 = {2f 75 70 64 31 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_2_9 = {66 72 6d 50 44 32 30 30 39 41 6c 65 72 74 00}  //weight: 2, accuracy: High
        $x_1_10 = {46 69 72 65 77 61 6c 6c 20 41 6c 65 72 74 00}  //weight: 1, accuracy: High
        $x_1_11 = "SOFTWARE\\Microsoft\\PDefender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

