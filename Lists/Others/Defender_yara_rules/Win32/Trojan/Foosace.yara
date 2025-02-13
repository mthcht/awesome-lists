rule Trojan_Win32_Foosace_I_2147694135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.I!dha"
        threat_id = "2147694135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 00 00 00 c7 05 ?? ?? ?? ?? 2c 00 00 00 c7 05 ?? ?? ?? ?? 40 00 00 00 c7 05 ?? ?? ?? ?? f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {67 53 68 61 72 65 64 49 6e 66 6f 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foosace_J_2147694516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.J!dha"
        threat_id = "2147694516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 69 65 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 73 36 34 00}  //weight: 1, accuracy: High
        $x_1_3 = "/%s%s%s/?%s=%s" ascii //weight: 1
        $x_1_4 = {66 33 55 fc 66 d1 ea 0f b7 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Foosace_C_2147694677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.C!dha"
        threat_id = "2147694677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%.2x%.2x%.2x%.2x" ascii //weight: 1
        $x_1_2 = {25 73 2f 63 67 69 2d 62 69 6e 2f 25 73 2e 63 67 69 3f 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 73 3a 25 2e 38 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 6e 69 74 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foosace_C_2147694677_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.C!dha"
        threat_id = "2147694677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8d 41 01 89 45 14 8a 44 0e fe 02 c3 8d 51 fe 02 c2 c0 e0 04 8d 79 ff 83 e7 07 32 04 37 8b 7d 14 02 da 83 e7 07 32 1c 37 8b d1 83 e2 07 22 1c 32 8b 55 f8 f6 eb 30 04 0a 8b 4d 14 8d 41 fe 83 f8 08}  //weight: 6, accuracy: High
        $x_2_2 = "Applicate" ascii //weight: 2
        $x_2_3 = "coreshell" ascii //weight: 2
        $x_4_4 = {31 db 89 55 98 89 da f7 f6 05 02 00 00 00 0f af ff 81 c7 05 00 00 00 39 f8 0f 84 62 07 00 00 8b 45 98 89 45 94 e9 55 00 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af c0 69 c0 07 00 00 00 2d 01 00 00 00 0f af c9 39 c8 0f 84 82 07 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af c0 69 c0 07 00 00 00 2d 01 00 00 00 0f af c9 39 c8 0f 84 5e 07 00 00 b8 00 00 00 00 89 45 94 e9 00 00 00 00 8b 45 94 8b 4d c4 89 01 b8 02 00 00 00 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af c9 81 c1 01 00 00 00 31 f6 89 55 90 89 f2 f7 f1 05 02 00 00 00 8b 4d 90 0f af c9 81 c1 05 00 00 00 39 c8}  //weight: 4, accuracy: Low
        $x_2_5 = "\\chkdbg.log" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Foosace_D_2147694678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.D!dha"
        threat_id = "2147694678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 2e 32 64 25 2e 32 64 25 2e 32 64 25 2e 32 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 73 00 20 00 49 00 44 00 3a 00 25 00 64 00 20 00 50 00 61 00 74 00 68 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 74 00 72 00 74 00 00 00 76 00 69 00 72 00 74 00 00 00 63 00 72 00 74 00 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 63 68 65 63 6b 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foosace_D_2147694678_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.D!dha"
        threat_id = "2147694678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 44 24 24 8a da c0 e3 03 8d 54 d0 fe 8d 71 02 89 54 24 2c 8d 46 01 8a d1 83 e0 07 02 d3 8d 6e ff 8a 04 38 83 e5 07 32 c2 8b d6 83 e2 07 22 04 3a 8a 54 3e fe 02 d1 02 d3 c0 e2 04 32 14 2f f6 ea 8b 54 24 2c 30 04 16 8b 44 24 28 41 46 3b c8}  //weight: 4, accuracy: High
        $x_2_2 = {c0 e2 03 8d 71 02 8d 46 01 8a d9 83 e0 07 02 da 8d 6e ff 8a 04 38 83 e5 07 32 c3 8b de 83 e3 07 22 04 3b 8a 5c 37 fe 02 d9 02 da c0 e3 04 32 1c 2f f6 eb 8b 5c 24 28 30 04 33 41 46 83 fe 0a}  //weight: 2, accuracy: High
        $x_2_3 = "Initialize" ascii //weight: 2
        $x_2_4 = "\\chkdbg.log" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Foosace_E_2147694679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.E!dha"
        threat_id = "2147694679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 08 6a 07 03 c7 33 d2 89 45 e0 8d 47 01 5b f7 f3 8a d9 6a 07 02 5d 0f 8a 04 32 33 d2 f6 eb 8a d8 8b c7 5f f7 f7 8b 7d f8 6a 07 8a 44 37 fe 02 45 fc 02 1c 32 b2 03 f6 ea 88 5d 13 8a d8 02 d9 8d 47 ff 33 d2 59 f7 f1 8a 4d 13 8b 45 e0 c0 e3 06 02 1c 32 32 cb 30 08 8b 4d 14 41 47 3b 4d e4 89 4d 14 89 7d f8 72 97}  //weight: 4, accuracy: High
        $x_2_2 = "Init1" ascii //weight: 2
        $x_2_3 = "70.85.221.10" ascii //weight: 2
        $x_2_4 = "~xh/ch.cgi" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foosace_E_2147694679_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.E!dha"
        threat_id = "2147694679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6c 6c 2e 64 6c 6c [0-2] 53 74 61 72 74}  //weight: 1, accuracy: Low
        $x_2_2 = {59 5a 5a 41 4d 75 74 65 78 00}  //weight: 2, accuracy: High
        $x_1_3 = {49 6e 69 74 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {f7 f7 8b 45 14 c1 eb 07 32 1c 02 8d 46 01 33 d2 f7 f7 8a 45 0f 02 c1 8b 4d 14 8a 0c 0a}  //weight: 1, accuracy: High
        $x_1_5 = {8a 54 37 fe 03 d3 03 d1 d3 ea 32 c2 8d 56 ff 83 e2 07 8a 1c 3a 8a 14 2e 32 c3 32 d0 41 88 14 2e 46 83 fe 0a 7c bb}  //weight: 1, accuracy: High
        $x_1_6 = {f7 f7 2b 4d ec 8b 45 e0 f7 d9 1b c9 f7 d1 23 ca 33 d2 f7 f6 89 4d fc 3b ca 89 55 e0 73 7a}  //weight: 1, accuracy: High
        $x_1_7 = {03 c1 03 45 14 d3 e8 8d 4e ff 83 e1 07 32 d0 32 14 39 8b 45 f8 30 14 30 8b 75 f4 8d 56 fe 83 fa 08 72 b7}  //weight: 1, accuracy: High
        $x_1_8 = {8a c3 03 db 03 db 03 db 8b fe 2b fb 89 7d e8 bf 01 00 00 00 2b fb 89 7d ec 02 c0 bf 03 00 00 00 2b fb 02 c0 89 7d 0c 02 c0 bf 02 00 00 00 2b fb 88 45 13 8d 04 0b 89 7d 14 8b 7d 0c 8a 5d 13 02 d9 8b 4d 14 03 c8 03 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Foosace_F_2147694680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.F!dha"
        threat_id = "2147694680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 69 76 65 20 25 73 20 6e 6f 74 20 66 6f 75 6e 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 66 73 64 61 74 61 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 6b 6e 64 61 74 61 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "Reg plugins:" ascii //weight: 1
        $x_1_5 = "Err open key %.8x-%s:%.8x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Foosace_B_2147696869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.B!dha"
        threat_id = "2147696869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/~%s/cgi-bin/%s.cgi?%s" ascii //weight: 2
        $x_2_2 = {62 72 76 63 00 73 70 74 72 00 71 66 61 00 6d 70 6b 00}  //weight: 2, accuracy: High
        $x_2_3 = {64 6c 6c 3a 25 2e 38 78 00 69 6e 73 3a 25 2e 38 78 00}  //weight: 2, accuracy: High
        $x_1_4 = {6e 65 74 75 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 6c 6c 2e 64 6c 6c 00 49 6e 69 74 31 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Foosace_A_2147696870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.A!dha"
        threat_id = "2147696870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/~%s/cgi-bin/%s.cgi?%s" ascii //weight: 2
        $x_2_2 = {62 72 76 63 00 73 70 74 72 00 71 66 61 00 6d 70 6b 00}  //weight: 2, accuracy: High
        $x_2_3 = {64 6c 6c 3a 25 2e 38 78 00 69 6e 73 3a 25 2e 38 78 00}  //weight: 2, accuracy: High
        $x_1_4 = {6d 73 6d 76 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 65 74 75 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foosace_K_2147705792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.K!dha"
        threat_id = "2147705792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 c1 74 0e 00 00 00 c7 44 c1 70 ?? ?? ?? ?? c7 44 c1 7c 0f 00 00 00 c7 44 c1 78 ?? ?? ?? ?? c7 84 c1 84 00 00 00 11 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 81 74 01 00 00 85 c0 0f 84 ?? 00 00 00 8b 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 ff d6 8b 0d ?? ?? ?? ?? 89 81 58 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 82 e0 00 00 00 ff d0 83 c4 14 8d 4d ?? 51 8b 15 ?? ?? ?? ?? 8b 42 10 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Foosace_A_2147708279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.A!!Foosace.gen!dha"
        threat_id = "2147708279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "Foosace: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XSQWERSystemCritical" ascii //weight: 1
        $x_1_2 = "\\\\.\\mailslot\\check_mes_v5555" ascii //weight: 1
        $x_1_3 = "\\\\.\\mailslot\\9dd9d3ec-1c0f-4626-a675-9029bb8e603" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Foosace_M_2147724939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foosace.M!dha"
        threat_id = "2147724939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 0c 59 85 db 7e 2c 57 8b 7d 08 2b fe 8d 0c 30 c7 45 ?? ?? ?? ?? ?? 33 d2 f7 75 ?? 8a 82 ?? ?? 00 10 32 04 0f 88 01 8b 45 0c 40 89 45 0c 3b c3 7c db}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 8b d0 59 85 db 7e 1f 57 8b 7d 08 2b fa 8b c6 8d 0c 16 83 e0 0f 8a 80 ?? ?? 00 10 32 04 0f 46 88 01 3b f3 7c e8 5f 5e}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 4e 4f 45 50 00 32 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

