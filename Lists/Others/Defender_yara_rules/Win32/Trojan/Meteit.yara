rule Trojan_Win32_Meteit_A_2147646658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.A"
        threat_id = "2147646658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WbemScripting.SWbemLastError\\CurVer" wide //weight: 1
        $x_1_2 = "SpynetReportSrvc.asmx" ascii //weight: 1
        $x_1_3 = {6d 65 67 61 64 6f 6d 65 6e 2e 63 6f 6d 2f 63 6c 61 73 73 [0-2] 2f 73 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = {3c 7c 3e 61 64 76 [0-2] 3c 7c 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Meteit_B_2147652095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.B"
        threat_id = "2147652095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "patr1ckjane.com/runk/s.php" ascii //weight: 1
        $x_1_2 = "whoismistergreen.com/runk/c.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meteit_C_2147652521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.C"
        threat_id = "2147652521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 1c 8b 7c 24 14 8b f5 2b fd 8a 04 37 6a 02 50 e8 8e ff ff ff 83 c4 08 88 06 46 4b 75 ec}  //weight: 2, accuracy: High
        $x_2_2 = {8b 44 24 04 8b 4c 24 08 25 ff 00 00 00 85 c9 7e 0c d1 e0 f6 c4 01 74 02 0c 01 49 75 f4}  //weight: 2, accuracy: High
        $x_1_3 = "WbemScripting.SWbemLastError\\CurVer\\" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Cryptography" wide //weight: 1
        $x_1_5 = {2f 53 70 79 6e 65 74 52 65 70 6f 72 74 53 72 76 63 2e 61 73 6d 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 72 6f 2f 63 6f 69 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 72 69 6d 2f 63 65 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {2e 30 3c 7c 3e ?? ?? ?? ?? ?? ?? ?? 3c 7c 3e 30 3c 7c 3e 00}  //weight: 1, accuracy: Low
        $x_1_9 = "<|>sol_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meteit_D_2147655081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.D"
        threat_id = "2147655081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 03 01 00 00 50 8b 45 ?? 53 03 c7 33 f6 ff d0 48 78 24 8a 8c 05 ?? ?? ff ff 8d 94 05 ?? ?? ff ff 80 f9 5c 74 11 80 f9 41 7c e5 80 f9 5a 7f e0 80 c1 20 88 0a eb d9}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc bb bb 00 00 81 7d fc aa aa 00 00 72 04 83 65 fc 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meteit_E_2147670416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.E"
        threat_id = "2147670416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 fc bb bb 00 00 81 7d fc aa aa 00 00 72 04 83 65 fc 00 8b 45 ?? 8b 4d}  //weight: 10, accuracy: Low
        $x_1_2 = {ff 10 33 c9 39 4b 08 0f 85 ?? ?? ?? ?? b8 ?? ?? ?? ?? 89 4d f8 2b c6 89 4d fc 89 45 f0 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 10 33 c0 39 43 08 0f 85 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 45 f8 2b d6 89 45 fc 89 55 f0 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meteit_F_2147679993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.F"
        threat_id = "2147679993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 03 01 00 00 50 8b 45 ?? 53 03 c7 33 f6 ff d0 48 78 24 8a 8c 05 ?? ?? ff ff 8d 94 05 ?? ?? ff ff 80 f9 5c 74 11 80 f9 41 7c e5 80 f9 5a 7f e0 80 c1 20 88 0a eb d9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 0c 81 e1 ff 0f 00 00 03 cb 01 39 8b 48 04 ff 45 08 83 e9 08 42 d1 e9 42 39 4d 08 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meteit_H_2147689977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meteit.H"
        threat_id = "2147689977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 34 39 45 8c 75 54 8b 45 b0 03 45 90 0f b6 48 20 8b 45 90 83 c0 20 8b 55 b0 0f b6 b2 80 01 00 00 83 c6 04 33 d2 f7 f6 0f b6 c2}  //weight: 1, accuracy: High
        $x_1_2 = {0b ca 8b 55 b4 0f b6 52 2c f7 d2 8b 75 b4 0f b6 76 2c 0b d6 23 ca 23 c1 83 f8 62 0f 85 c9 04 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f7 d0 0b f0 23 ce 88 4d f5 8b 45 b0 03 85 d4 fe ff ff 8a 4d f5 88 88 d8 13 00 00 e9 21 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

