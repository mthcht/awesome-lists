rule Trojan_Win32_Cleaman_A_2147645494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cleaman.A"
        threat_id = "2147645494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cleaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 e9 6a 04 43 53 ff d6 85 c0 75 ?? 2b ?? ?? ?? 83 ef 05 89 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 50 00 00 66 39 4e 02 75 64 66 83 3e 02 75 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cleaman_B_2147647326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cleaman.B"
        threat_id = "2147647326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cleaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 56 ff d7 b8 ?? 87 00 00 33 c9 66 3b d8 0f 94 c1}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 04 31 d0 c8 88 04 31 8b c6 41 8d 78 01 8b ff 8a 10 40 84 d2 75 f9}  //weight: 2, accuracy: High
        $x_2_3 = {75 04 c6 45 00 e9 8d 45 01 6a 04 50 89 44 24 18}  //weight: 2, accuracy: High
        $x_2_4 = {8a 08 d0 c9 88 08 40 80 38 00 75 f4 80 3d}  //weight: 2, accuracy: High
        $x_1_5 = "getActiveDesktop" ascii //weight: 1
        $x_1_6 = "sw-dll.dll" ascii //weight: 1
        $x_1_7 = "auditpol" ascii //weight: 1
        $x_1_8 = {2e 6c 6f 67 00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 00 00 64 70 6c 61 79 73 76 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cleaman_D_2147650366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cleaman.D"
        threat_id = "2147650366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cleaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ca c1 e1 07 d1 ea 0b ca 88 88 ?? ?? ?? ?? 40}  //weight: 5, accuracy: Low
        $x_1_2 = {75 04 c6 45 00 e9 6a 04 8d 45 01 50 2b f5 83 c6 fb}  //weight: 1, accuracy: High
        $x_1_3 = {8b f7 f7 de 80 3c 16 5c 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cleaman_E_2147651002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cleaman.E"
        threat_id = "2147651002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cleaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 2c fd ff ff ?? ?? ?? ?? 8b 45 ec c6 40 01 65 8b 4d ec c6 41 08 65}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fa 00 8b 45 ec c6 40 01 65 8b 4d ec c6 41 04 70 8d 55 f4 52 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 04 4a c1 f8 0c 83 f8 03 75 ?? c7 85 78 ff ff ff ?? ?? 00 00 8b 4d 8c 8b 95 7c ff ff ff 0f b7 04 4a 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = "\\drivers\\3r5werg.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

