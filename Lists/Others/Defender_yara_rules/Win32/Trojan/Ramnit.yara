rule Trojan_Win32_Ramnit_A_2147632845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.A"
        threat_id = "2147632845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 8a 1c 32 32 1f 88 1f 47 4a e2 ed}  //weight: 1, accuracy: High
        $x_1_2 = {6a 05 8f 45 f0 6a 04 8d 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_A_2147632845_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.A"
        threat_id = "2147632845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 52 56 57 6a 0c ff 75 08 e8 ?? ?? ff ff 89 ?? ?? 83 c0 08 8b c8 8b 75 0c 6a 19 52 e8 ?? ?? ff ff 04 61 88 06 46 e2 f1 c6 06 00 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 8b 75 1c 8b 7d 08 8b 55 10 3b 55 10 75 04 03 55 14 4a 8a 1a 32 1f 83 7d 18 00 75 0f 88 1e 46 80 fb 00 74 1e 39 75 20 76 19 eb 07 0a db 75 03 ff 4d 18 47 4a e2 d3 ff 75 18 8f 45 fc 83 7d 18 00 75 bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_C_2147640304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.C"
        threat_id = "2147640304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 68 02 00 00 00 68 00 30 00 10 52 ff 75 08 e8 ?? ?? ?? ?? 0b c0 75 05 8b 45 08 eb 01 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_A_2147642898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.gen!A"
        threat_id = "2147642898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 70 1c 8f 45 f8 ff 70 38 8f 45 f4 8b 45 fc 05 00 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 13 80 3f 0d 75 0e 80 7f 01 0a 75 08 80 3e 0a 75 03 47 eb 19}  //weight: 1, accuracy: High
        $x_1_3 = {40 c6 00 5c 40 c6 00 00 6a 00 8f 85 f4 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ramnit_A_2147642898_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.gen!A"
        threat_id = "2147642898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 65 6c 65 76 61 74 65 00 61 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {34 35 42 6e 39 39 67 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 73 63 73 76 63 00 57 69 6e 44 65 66 65 6e 64 00 77 75 61 75 73 65 72 76 00 4d 70 73 53 76 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 36 33 31 44 32 34 30 38 44 34 34 43 34 66 34 37 41 43 36 34 37 41 42 39 36 39 38 37 44 34 44 35 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 61 70 70 6f 72 74 4d 67 6d 74 53 65 72 76 69 63 65 00 4d 69 63 6f 72 73 6f 66 74 20 57 69 6e}  //weight: 1, accuracy: High
        $x_1_6 = "\\demetra\\loader~1\\drivers\\ssdt\\" ascii //weight: 1
        $x_1_7 = {65 78 65 63 00 6b 6f 73 00 73 63 72 65 65 6e 00 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 46 69 72 65 77 61 6c 6c 4f 76 65 72 72 69 64 65 00 55 70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_9 = {22 25 25 77 69 6e 64 69 72 25 25 5c 73 79 73 74 65 6d 33 32 5c 73 64 62 69 6e 73 74 2e 65 78 65 22 20 2f 71 20 2f 75 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_10 = {55 41 43 5f 62 79 70 61 73 73 65 64 00 00 00 00 54 52 55 45 00}  //weight: 1, accuracy: High
        $x_1_11 = {52 61 70 70 6f 72 74 00 00 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00 63 6f 6e 73 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_12 = {6c 6f 61 64 65 72 2e 65 78 65 00 5f 41 70 70 6c 79 45 78 70 6c 6f 69 74 40 34 00 5f 43 68 65 63 6b 42 79 70 61 73 73 65 64 40 30 00}  //weight: 1, accuracy: High
        $x_1_13 = {4d 70 73 53 76 63 00 77 73 63 73 76 63 00 57 69 6e 44 65 66 65 6e 64 00 77 75 61 75 73 65 72 76}  //weight: 1, accuracy: High
        $x_1_14 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45 00 00 00 01 88 52 00 00 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 4c 00 6f 00 77 00 5c 00 63 00 6d 00 64 00 2e 00 25 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 43 68 65 63 6b 42 79 70 61 73 73 65 64 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_16 = {25 54 45 4d 50 25 5c 70 2e 65 78 65 00 00 00 00 22 20 25 54 45 4d 50 25 5c 70 2e 65 78 65 00 00 63 6f 70 79 20 2f 62 20 22 00}  //weight: 1, accuracy: High
        $x_1_17 = {63 6f 6d 2e 25 73 2e 73 64 62 00 00 25 73 5c 63 6d 64 2e 25 73 2e 62 61 74 00 00 00 75 73 65 72 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_18 = {6a 0c ff 75 08 e8 ?? ?? ff ff 89 55 fc 83 c0 08 8b c8 8b 75 0c 6a 19 52 e8 ?? ?? ff ff 04 61 88 06 46 e2 f1 c6 06 00}  //weight: 1, accuracy: Low
        $x_1_19 = {6a 19 52 e8 [0-8] ?? ?? ?? ?? 04 61 [0-8] 88 06 [0-8] 46 [0-8] e2 ?? c6 06 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ramnit_D_2147645306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.D"
        threat_id = "2147645306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 f0 68 2e 73 79 73 56 6a}  //weight: 1, accuracy: High
        $x_1_2 = {74 68 40 c6 00 5c 40 c6 00 00 6a 00 8f 85}  //weight: 1, accuracy: High
        $x_1_3 = "RapportMgmt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ramnit_A_2147679637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.A!ftp"
        threat_id = "2147679637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "ftp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 65 74 44 72 69 76 65 00 00 00 00 46 74 70 43 6f 6e 74 72 6f 6c 00 00 00 00 00 00 33 32 62 69 74 20 46 54 50 00 00 00 57 69 6e 53 63 70 00 00 4c 65 61 70 46 74 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 0b 83 78 49 00 74 05 50 ff 50 49 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_A_2147679638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.A!vnc"
        threat_id = "2147679638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "vnc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 6e 63 2e 64 6c 6c 00 43 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65 00 4d 6f 64 75 6c 65 43 6f 64 65 00 53 74 61 72 74 52 6f 75 74 69 6e 65 00 53 74 6f 70 52 6f 75 74 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 74 6e 83 3c 24 4e 75 68 6a 00 8d 44 24 08 50 68 8d 49 37 29 e8 58 9f ff ff 6a 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_A_2147686460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.A!!Ramnit.gen!A"
        threat_id = "2147686460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "Ramnit: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 65 6c 65 76 61 74 65 00 61 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 73 63 73 76 63 00 57 69 6e 44 65 66 65 6e 64 00 77 75 61 75 73 65 72 76 00 4d 70 73 53 76 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 70 73 53 76 63 00 77 73 63 73 76 63 00 57 69 6e 44 65 66 65 6e 64 00 77 75 61 75 73 65 72 76}  //weight: 1, accuracy: High
        $x_1_4 = {5c 36 33 31 44 32 34 30 38 44 34 34 43 34 66 34 37 41 43 36 34 37 41 42 39 36 39 38 37 44 34 44 35 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 61 70 70 6f 72 74 4d 67 6d 74 53 65 72 76 69 63 65 00 4d 69 63 6f 72 73 6f 66 74 20 57 69 6e}  //weight: 1, accuracy: High
        $x_1_6 = "\\demetra\\loader~1\\drivers\\ssdt\\" ascii //weight: 1
        $x_1_7 = {65 78 65 63 00 6b 6f 73 00 73 63 72 65 65 6e 00 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {34 35 42 6e 39 39 67 54 00}  //weight: 1, accuracy: High
        $x_1_9 = {55 41 43 5f 62 79 70 61 73 73 65 64 00 00 00 00 54 52 55 45 00}  //weight: 1, accuracy: High
        $x_1_10 = {52 61 70 70 6f 72 74 00 00 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00 63 6f 6e 73 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {22 25 25 77 69 6e 64 69 72 25 25 5c 73 79 73 74 65 6d 33 32 5c 73 64 62 69 6e 73 74 2e 65 78 65 22 20 2f 71 20 2f 75 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_12 = {6c 6f 61 64 65 72 2e 65 78 65 00 5f 41 70 70 6c 79 45 78 70 6c 6f 69 74 40 34 00 5f 43 68 65 63 6b 42 79 70 61 73 73 65 64 40 30 00}  //weight: 1, accuracy: High
        $x_1_13 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45 00 00 00 01 88 52 00 00 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 4c 00 6f 00 77 00 5c 00 63 00 6d 00 64 00 2e 00 25 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 43 68 65 63 6b 42 79 70 61 73 73 65 64 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_15 = {25 54 45 4d 50 25 5c 70 2e 65 78 65 00 00 00 00 22 20 25 54 45 4d 50 25 5c 70 2e 65 78 65 00 00 63 6f 70 79 20 2f 62 20 22 00}  //weight: 1, accuracy: High
        $x_1_16 = "\\Windows Defender\\Exclusions\\Processes  \" /v svchost.exe /t  REG_DWORD /d 0" ascii //weight: 1
        $x_1_17 = {63 6f 6d 2e 25 73 2e 73 64 62 00 00 25 73 5c 63 6d 64 2e 25 73 2e 62 61 74 00 00 00 75 73 65 72 6e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ramnit_B_2147691387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.gen!B"
        threat_id = "2147691387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 70 1c 90 90 8f 45 f8 90 90 90 90 90 90 90 ff 70 38 90 90 8f 45 f4 90 90 90 90 90 90 8b 45 fc 05 00 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 13 80 3f 0d 75 0e 80 7f 01 0a 75 08 80 3e 0a 75 03 47 eb 19}  //weight: 1, accuracy: High
        $x_1_3 = {40 90 90 c6 00 5c 40 90 90 c6 00 00 90 90 33 c0 90 90 89 85 f4 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ramnit_I_2147722627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.I!bit"
        threat_id = "2147722627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4d 5a 00 00 66 39 01 75 f3 8b 41 3c 03 c1 81 38 50 45 00 00 75 e6 b9 ?? ?? ?? ?? 66 39 48 18 75 db}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 83 c2 ?? 83 e2 ?? 8b 45 08 8b 4d fc 8b 75 08 8b 54 90 ?? 33 14 8e 8b 45 fc 83 c0 ?? 83 e0 ?? 8b 4d 08 89 54 81 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 0c 8b 45 08 8b 52 04 33 14 08 b8 ?? ?? ?? ?? 6b c8 ?? 8b 45 08 8b 0c 08 c1 e9 ?? 33 d1 b8 ?? ?? ?? ?? 6b c8 ?? 8b 45 08 8b 0c 08 c1 e1 ?? 33 d1 8b 45 10 89 50 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_J_2147722841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.J!bit"
        threat_id = "2147722841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4d 5a 00 00 66 39 01 75 f3 8b 41 3c 03 c1 81 38 50 45 00 00 75 e6 b9 ?? ?? ?? ?? 66 39 48 18 75 db}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 83 c2 ?? 83 e2 ?? 8b 45 08 8b 4d fc 8b 75 08 8b 54 90 ?? 33 14 8e 8b 45 fc 83 c0 ?? 83 e0 ?? 8b 4d 08 89 54 81 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 18 8b 35 ?? ?? ?? ?? 8b ce ff 75 14 33 35 ?? ?? ?? ?? 83 e1 1f ff 75 10 d3 ce ff 75 0c ff 75 08 85 f6 75 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_K_2147730000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.K"
        threat_id = "2147730000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 84 24 d8 00 00 00 8b 5c 24 ?? 0f af 5c 24 ?? 8b 44 24 ?? 8b 54 24 ?? 83 eb 1a 83 7c 24 ?? 00 8d 34 02 75 ?? 8d 84 24 ?? ?? ?? 00 0f b7 d0 03 54 24 ?? 29 15 ?? ?? ?? 00 83 3d ?? ?? ?? 00 00 74 ?? 8b 84 24 ?? ?? 00 00 8d 0c 30 8b 44 24 ?? 99 f7 f9 8b 0d ?? ?? ?? 00 0f af c3 0f af 44 24 ?? 8d 3c 87 8a c3 32 06 83 7c 24 ?? 00 74 ?? 0f b6 4c 24 ?? 0f b7 15 ?? ?? ?? 00 03 ca 89 0d ?? ?? ?? 00 83 7c 24 ?? 00 75 ?? 8a 44 24 ?? 88 06 0f b7 f1 b8 85 91 76 ac f7 ee 03 d6 8b 74 24 ?? c1 fa 06 8b c2 c1 e8 1f 03 d0 2b 54 24 ?? 0f b6 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {d1 fa 6a 00 8b c2 6a ?? c1 e8 ?? 6a ?? 03 c2 51 8d 94 24 ?? ?? ?? 00 8b f8 52 0f af fd ff 15 ?? ?? ?? 00 8b 8c 24 ?? ?? 00 00 8a c3 32 44 24 ?? 88 44 24 ?? 8b c7 c1 e0 ?? 2b c8 2b 4c 24 ?? 01 4c 24 ?? 83 3d ?? ?? ?? 00 00 0f 85 ?? ?? 00 00 8d 94 24 ?? ?? 00 00 68 ?? ?? ?? 00 52 e8 ?? ?? ?? ff 6a ?? 8b f0 6a ?? 56 e8 ?? ?? ?? ff 56 e8 ?? ?? ?? ff 8b f0 8d 46 ?? 50 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? 00 83 c4 1c 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ramnit_AK_2147730812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.AK"
        threat_id = "2147730812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 6e 63 69 6e 73 74 61 6c 6c 2e 64 6c 6c 00 43 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65 00 4d 6f 64 75 6c 65 43 6f 64 65 00 53 74 61 72 74 52 6f 75 74 69 6e 65 00 53 74 6f 70 52 6f 75 74 69 6e 65}  //weight: 1, accuracy: High
        $x_1_2 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 00 00 00 41 63 49 6e 6a 65 63 74 44 6c 6c 3a}  //weight: 1, accuracy: High
        $x_1_3 = {54 68 69 73 20 0e 70 72 6f 67 67 61 6d 87 63 47 6e 1f 4f 74 e7 62 65 af cf 75 5f 98 69 06 44 4f 7e 53 03 6d 6f 64 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_C_2147740303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.gen!C"
        threat_id = "2147740303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 65 6c 65 76 61 74 65 00 61 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 73 63 73 76 63 00 57 69 6e 44 65 66 65 6e 64 00 77 75 61 75 73 65 72 76 00 4d 70 73 53 76 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 70 73 53 76 63 00 77 73 63 73 76 63 00 57 69 6e 44 65 66 65 6e 64 00 77 75 61 75 73 65 72 76}  //weight: 1, accuracy: High
        $x_1_4 = {5c 36 33 31 44 32 34 30 38 44 34 34 43 34 66 34 37 41 43 36 34 37 41 42 39 36 39 38 37 44 34 44 35 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 61 70 70 6f 72 74 4d 67 6d 74 53 65 72 76 69 63 65 00 4d 69 63 6f 72 73 6f 66 74 20 57 69 6e}  //weight: 1, accuracy: High
        $x_1_6 = "\\demetra\\loader~1\\drivers\\ssdt\\" ascii //weight: 1
        $x_1_7 = {65 78 65 63 00 6b 6f 73 00 73 63 72 65 65 6e 00 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {34 35 42 6e 39 39 67 54 00}  //weight: 1, accuracy: High
        $x_1_9 = {55 41 43 5f 62 79 70 61 73 73 65 64 00 00 00 00 54 52 55 45 00}  //weight: 1, accuracy: High
        $x_1_10 = {52 61 70 70 6f 72 74 00 00 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00 63 6f 6e 73 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {22 25 25 77 69 6e 64 69 72 25 25 5c 73 79 73 74 65 6d 33 32 5c 73 64 62 69 6e 73 74 2e 65 78 65 22 20 2f 71 20 2f 75 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_12 = {6c 6f 61 64 65 72 2e 65 78 65 00 5f 41 70 70 6c 79 45 78 70 6c 6f 69 74 40 34 00 5f 43 68 65 63 6b 42 79 70 61 73 73 65 64 40 30 00}  //weight: 1, accuracy: High
        $x_1_13 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45 00 00 00 01 88 52 00 00 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 4c 00 6f 00 77 00 5c 00 63 00 6d 00 64 00 2e 00 25 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 43 68 65 63 6b 42 79 70 61 73 73 65 64 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_15 = {25 54 45 4d 50 25 5c 70 2e 65 78 65 00 00 00 00 22 20 25 54 45 4d 50 25 5c 70 2e 65 78 65 00 00 63 6f 70 79 20 2f 62 20 22 00}  //weight: 1, accuracy: High
        $x_1_16 = "\\Windows Defender\\Exclusions\\Processes  \" /v svchost.exe /t  REG_DWORD /d 0" ascii //weight: 1
        $x_1_17 = {63 6f 6d 2e 25 73 2e 73 64 62 00 00 25 73 5c 63 6d 64 2e 25 73 2e 62 61 74 00 00 00 75 73 65 72 6e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ramnit_E_2147740305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.gen!E"
        threat_id = "2147740305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 61 6d 65 6c 6c 69 61 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = "--disable-http2 --disable-quic --disk-cache-size=1" ascii //weight: 2
        $x_2_3 = {66 69 72 65 66 6f 78 2e 65 78 65 00 6d 69 63 72 6f 73 6f 66 74 65 64 67 65 63 70 2e 65 78 65 00 74 68 75 6e 64 65 72 62 69 72 64 2e 65 78 65 00 49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 00}  //weight: 2, accuracy: High
        $x_1_4 = {43 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65 00 4d 6f 64 75 6c 65 43 6f 64 65 00 53 74 61 72 74 52 6f 75 74 69 6e 65 00 53 74 6f 70 52 6f 75 74 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {32 74 6f 70 52 6f 75 74 69 6e 65 00 31 74 61 72 74 52 6f 75 74 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {33 6f 64 75 6c 65 43 6f 64 65 00 00 34 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65}  //weight: 1, accuracy: High
        $x_1_7 = "pref(\"network.http.spdy.enabled.http2\", false);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ramnit_F_2147740445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.gen!F"
        threat_id = "2147740445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 0c 8b 7d 08 8b 75 10 ba 00 00 00 00 0b d2 75 04 8b 55 14 4a 8a 1c 32 32 1f 88 1f 47 4a e2 ed}  //weight: 1, accuracy: High
        $x_2_3 = {66 42 31 6f 4e 35 66 72 47 71 66 00}  //weight: 2, accuracy: High
        $x_2_4 = {66 45 34 68 4e 79 31 4f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramnit_E_2147740446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.E!!Ramnit.gen!E"
        threat_id = "2147740446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "Ramnit: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "E: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 61 6d 65 6c 6c 69 61 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = "--disable-http2 --disable-quic --disk-cache-size=1" ascii //weight: 2
        $x_2_3 = {66 69 72 65 66 6f 78 2e 65 78 65 00 6d 69 63 72 6f 73 6f 66 74 65 64 67 65 63 70 2e 65 78 65 00 74 68 75 6e 64 65 72 62 69 72 64 2e 65 78 65 00 49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 00}  //weight: 2, accuracy: High
        $x_1_4 = {43 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65 00 4d 6f 64 75 6c 65 43 6f 64 65 00 53 74 61 72 74 52 6f 75 74 69 6e 65 00 53 74 6f 70 52 6f 75 74 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {32 74 6f 70 52 6f 75 74 69 6e 65 00 31 74 61 72 74 52 6f 75 74 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {33 6f 64 75 6c 65 43 6f 64 65 00 00 34 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65}  //weight: 1, accuracy: High
        $x_1_7 = "pref(\"network.http.spdy.enabled.http2\", false);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ramnit_F_2147740447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramnit.F!!Ramnit.gen!F"
        threat_id = "2147740447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramnit"
        severity = "Critical"
        info = "Ramnit: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 0c 8b 7d 08 8b 75 10 ba 00 00 00 00 0b d2 75 04 8b 55 14 4a 8a 1c 32 32 1f 88 1f 47 4a e2 ed}  //weight: 1, accuracy: High
        $x_2_3 = {66 42 31 6f 4e 35 66 72 47 71 66 00}  //weight: 2, accuracy: High
        $x_2_4 = {66 45 34 68 4e 79 31 4f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

