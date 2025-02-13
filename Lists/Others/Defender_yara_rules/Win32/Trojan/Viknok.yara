rule Trojan_Win32_Viknok_A_2147680233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viknok.A"
        threat_id = "2147680233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viknok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 fa 8b 4f 20 8b 77 1c 8b 5f 24 03 ca 03 f2 03 da 83 7f 18 00}  //weight: 1, accuracy: High
        $x_1_2 = {eb 11 81 7d fc ?? ?? 00 00 73 14 6a 64 ff 55 ?? ff 45 ?? e8 ?? ?? ?? ?? 50 ff d3 85 c0 74 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Viknok_B_2147681458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viknok.B"
        threat_id = "2147681458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viknok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 6a 06 ff b5 ?? ?? ff ff 83 ee 05 ff 75 08 c6 45 ?? e9 89 75 ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 8b 70 20 8b 78 1c 8b 50 24 03 f3 03 fb 03 d3 83 78 18 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Viknok_C_2147684863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viknok.C"
        threat_id = "2147684863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viknok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "p=%u&t=%u&e=%u" ascii //weight: 1
        $x_1_2 = {8b 42 3c 03 c2 8b 78 78 89 45 ?? 85 ff 74 ?? 83 65 ?? 00 03 fa 8b 4f 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Viknok_D_2147687507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viknok.D"
        threat_id = "2147687507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viknok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 2d c7 00 5c 00 53 00 c7 40 04 65 00 73 00 c7 40 08 73 00 69 00 c7 40 0c 6f 00 6e 00 89 50 10 83 c0 14 83 c1 30 66 89 08}  //weight: 1, accuracy: High
        $x_1_2 = {b8 bb bb aa ee 8a 5c 31 ff 32 d8 66 89 5c 4a fe 49 75 f2 5b c3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 46 08 eb 0e f6 40 08 02 74 06 83 78 04 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 32 66 83 c0 30 c7 02 5c 00 53 00 c7 42 04 65 00 73 00 c7 42 08 73 00 69 00 c7 42 0c 6f 00 6e 00 44 89 42 10 66 89 42 14 48 83 c2 16}  //weight: 1, accuracy: High
        $x_1_5 = {48 b8 bb bb aa ee 00 00 00 00 8a 5c 31 ff 32 d8 66 89 5c 4a fe 48 ff c9 75 f0 5b c3}  //weight: 1, accuracy: High
        $x_1_6 = {6c 08 0f 4e 74 4f 70 65 6e 46 69 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Viknok_2147688096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viknok!patched"
        threat_id = "2147688096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viknok"
        severity = "Critical"
        info = "patched: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ef 63 3c 22 05 81 c7 63 3c 22 05 66 81 c1 a9 79 66 81 e9 a9 79 51 81 c1 22 1c 00 00 8a 9c 31 dd e3 ff ff 59 05 d7 c6 78 25 2d d7 c6 78 25 32 d8 66 2d dd 18 66 05 dd 18 52 81 c2 43 01 00 00 66 89 9c 4a bb fe ff ff 5a 81 c3 4c 80 5a 57 81 eb 4c 80 5a 57 49 75 a8 80 ec d6}  //weight: 1, accuracy: High
        $x_1_2 = {81 ef 51 6a 00 00 8d 8f 51 6a 00 00 5f 66 81 ea 63 bf 66 81 c2 63 bf 51 81 eb 21 fd 4e 28 81 c3 21 fd 4e 28 68 ?? ?? ?? ?? 58 04 69 2c 69 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {66 89 87 3a 54 00 00 81 c7 14 54 00 00 66 81 e9 4e 3c 66 81 c1 4e 3c e8 fb 05 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

