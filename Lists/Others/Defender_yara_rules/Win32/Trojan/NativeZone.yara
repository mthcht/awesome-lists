rule Trojan_Win32_NativeZone_A_2147781393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NativeZone.A!dha"
        threat_id = "2147781393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NativeZone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 53 79 73 74 65 6d 43 65 72 74 69 66 69 63 61 74 65 73 5c 4c ?? 62 5c 43 65 72 74 50 4b 49 50 72 6f 76 69 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 67 6c 47 65 74 43 6f 6e 66 69 67 73 [0-4] 25 77 73 25 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {25 77 73 25 73 [0-4] 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 25 73 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 61 74 69 76 65 43 61 63 68 65 53 76 63 2e 64 6c 6c [0-4] 5f 63 6f 6e 66 69 67 4e 61 74 69 76 65 43 61 63 68 65 00}  //weight: 1, accuracy: Low
        $x_2_5 = {68 04 01 00 00 ?? ?? ?? ?? ?? ?? ?? 6a 00 50 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 6a 00 6a 00 6a 1a 6a 00 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 04 01 00 00 50 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 f8 ff 74 ?? a8 10 75 ?? 6a 44 ?? ?? ?? ?? 0f 57 c0 6a 00 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NativeZone_B_2147781664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NativeZone.B!dha"
        threat_id = "2147781664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NativeZone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cc b8 01 00 00 00 c2 0c 00 cc cc cc cc cc cc cc cc b8 0c 00 00 00 c3 cc cc cc cc cc cc cc cc cc cc 55 8b ec 83 ec 34 a1 00 30 01 10 33 c5 89 45 fc 56 57 b9 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NativeZone_C_2147781730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NativeZone.C!dha"
        threat_id = "2147781730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NativeZone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 4d 52 41 48 55 e5 89 81 48 20 ec 00 00 48 00 1d ?? ff ea ff ff 89 48 48 df c3 81 5f 88 00 01 d3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 02 89 44 24 ?? 8b 44 24 ?? 39 44 24 ?? 7d ?? 8b 44 24 ?? ff c0 48 98 48 8d 0d ?? ?? ?? ?? 48 63 54 24 ?? 48 8b 9c 24 ?? ?? ?? ?? 0f b6 04 01 88 04 13 48 63 44 24 ?? 48 8d 0d ?? ?? ?? ?? 8b 54 24 ?? ff c2 48 63 d2 48 8b 9c 24 ?? ?? ?? ?? 0f b6 04 01 88 04 13}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 55 73 65 72 73 5c 64 65 76 5c 44 65 73 6b 74 6f 70 5c eb 82 98 ed 83 80 eb 82 98 ea b2 8c 20 ed 95 98 eb 8b a4 5c 44 6c 6c ?? 5c 78 ?? ?? 5c 52 65 6c 65 61 73 65 5c 44 6c 6c ?? 2e 70 64 62 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NativeZone_D_2147781813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NativeZone.D!dha"
        threat_id = "2147781813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NativeZone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b f7 49 8b dd 4d 2b f5 bf 02 00 00 00 0f 1f 84 00 00 00 00 00 4d 8d 04 1e 4c 8b ce 48 8b d3 48 8d 4c 24 38 e8 ?? ?? ?? ?? 48 83 c3 10 48 83 ef 01 75 e2 48 8b ce e8 ?? ?? ?? ?? 41 0f 10 07 48 8b 44 24 20 0f 11 45 00 41 0f 10 4f 10 0f 11 4d 10 48 83 c5 20 49 83 ec 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NativeZone_E_2147788505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NativeZone.E!dha"
        threat_id = "2147788505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NativeZone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 50 50 44 41 54 41 00 5c 00 00 00 2e 5c 00 00 72 75 6e 74 69 6d 65 6d 73 74 72 63 2e 65 78 65 00 00 00 00 73 68 61 72 65 64 72 75 ?? 74 69 6d 65 74 72 63 2e 64 6c 6c 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 ?? 73 69 6f 6e 5c 52 75 6e 00 00 00 22 2c 49 6e 66 6c 61 74 65 48 61 73 68 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 00 00 4d 53 56 52 75 6e 74 69 6d 65 00}  //weight: 2, accuracy: Low
        $x_1_3 = {5e 87 44 24 04 89 54 24 ?? ba 29 cb 07 19 87 54 24 ?? 87 04 24 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {87 3c 24 89 7c 24 c0 87 7c 24 04 89 4c 24 ?? 87 3c 24 89 74 24 ?? be 42 41 4c ed 87 74 24 e0 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {87 3c 24 87 7c 24 04 87 3c ?? c3 0b d6 21 72 08 ff 77 08 8b 46 18 89 79 ?? 23 46 08 fa b9 a4 dd 7e b3}  //weight: 1, accuracy: Low
        $x_1_6 = {87 14 24 52 8b d6 5a 87 54 24 04 87 14 ?? 52 8b d7 5a c3 52 8b d6 5a 90 66 9d 31 08 f7 e6 ba 2d eb 38 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NativeZone_I_2147816922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NativeZone.I!dha"
        threat_id = "2147816922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NativeZone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {48 b8 30 be 7c 96 b5 04 c7 6e 48 ba 73 26 05 46 9e ac 17 f2}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

