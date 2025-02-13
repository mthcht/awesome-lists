rule Trojan_Win32_Oficla_A_141584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.A"
        threat_id = "141584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 44 24 08 c7 44 24 04 6e 7a 8b 67 c7 04 24 49 28 40 39 e8 ?? ?? ?? ?? 89 5c 24 08 c7 44 24 04 6a ab 05 d7 c7 04 24 49 28 40 39}  //weight: 10, accuracy: Low
        $x_10_2 = {c7 44 24 08 a1 5d b6 3e c7 44 24 04 39 28 67 73 89 04 24 e8 ?? ?? ?? ?? 89 1c 24 c7 44 24 08 d7 eb 95 7a c7 44 24 04 39 28 67 73}  //weight: 10, accuracy: Low
        $x_10_3 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 40 89 04 24 ff 15 ?? ?? ?? ?? 83 ec 1c 89 85 ?? ?? ff ff 83 c0 01 0f 84}  //weight: 10, accuracy: Low
        $x_10_4 = {83 ec 0c 89 7c 24 04 89 34 24 e8 ?? ?? ?? ?? 84 c0 75 15 89 7c 24 04 89 34 24 e8 ?? ?? ?? ?? 3c 01 19 db f7 d3 83 e3 02 89 f0}  //weight: 10, accuracy: Low
        $x_1_5 = {0f b6 71 01 0f b6 4d ec b8 01 00 00 00 d3 e0 85 45 ?? 0f 85 ?? ?? ff ff 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 89 c2 32 55 ?? 31 d6 83 fb 01 0f 85}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 79 01 0f b6 4d ?? bb 01 00 00 00 89 d8 d3 e0 85 45 ?? 0f 85 ?? ?? ff ff 8b 45 ?? ba ff ff ff ff c1 f8 03 8d 0c c5 08 00 00 00 83 f9 20 74 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_B_143021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.B"
        threat_id = "143021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 83 c3 01 83 c2 01 0f b6 c0 01 f0 88 01 83 c1 01 39 fb 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {81 e2 8c 00 00 00 89 95 d0 9d ff ff e9 84 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 8d d0 9d ff ff 0f b6 c0 31 c8 89 f1 89 85 80 9d ff ff 8b 85 c4 9d ff ff d3 e0 83 f8 3f 7f 9f}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 04 ce fe a3 73 c7 04 24 37 09 84 36 e8 ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 14 24 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Oficla_C_143022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.C"
        threat_id = "143022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4b 01 ba 01 00 00 00 30 03 0f b6 82 ?? ?? ?? ?? 83 c2 01 30 01 83 c1 01 83 fa 10 75 ec 83 c3 10 81 fb ?? ?? ?? ?? 75 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 7c fe ff ff c7 04 24 ?? ?? ?? ?? e8 ?? ?? 00 00 83 ec 04 83 f8 09 0f 8f 5a fd ff ff e9 5f fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 2f bf b5 98 c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? 89 c1 33 4d f0 81 c9 00 00 00 80 89 c8 f7 e2 c1 ea 1d}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 00 25 75 00 00 00 00 47 45 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Oficla_E_143849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.E"
        threat_id = "143849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 30 29 18 e8 ?? ?? ?? ?? 8d 95 ?? ?? ff ff b9 20 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 53 04 8d 93 ?? ?? 00 00 83 ec 08 89 ?? ?? ff d0 83 e8 01 83 ec 04 83 f8 01 76 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_E_143849_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.E"
        threat_id = "143849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 44 24 2c 13 04 18 5d 8d 85 ?? ?? ?? ?? ff d0 85 c0 75 04}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 44 24 2c 8b f7 08 3e 8d 85 ?? ?? ?? ?? ff d0 8b 54 24 40 52 ff d0}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b6 02 83 ?? 01 83 c2 01 33 05 ?? ?? ?? ?? 88 03 83 c3 01 3b ?? 48 77 ff ff 75 e4}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c0 01 89 44 24 08 69 c2 b7 c6 05 00 0f af d1 8d 75 f3 89 44 24 04 0f b6 c3 01 d0 89 04 24 e8}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 0c 8b 5d 08 c7 44 24 04 c9 f8 00 00 c7 04 24 00 00 00 00 89 44 24 08 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_E_143849_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.E"
        threat_id = "143849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {67 6c 61 76 00 70 72 65 70 75 73 6b 00 70 75 73}  //weight: 2, accuracy: High
        $x_2_2 = {67 6c 6c 61 76 00 67 6c 6c 61 76 00 70 70 75 73}  //weight: 2, accuracy: High
        $x_2_3 = {67 74 74 61 76 00 67 74 74 61 76 00 70 70 75 73}  //weight: 2, accuracy: High
        $x_2_4 = {67 69 69 61 76 00 67 69 69 61 76 00 70 72 65 62}  //weight: 2, accuracy: High
        $x_8_5 = {c7 44 24 0c 3f 00 0f 00 c7 44 24 08 00 00 00 00 c7 04 24 (00|02) 00 00 80}  //weight: 8, accuracy: Low
        $x_1_6 = {83 c2 01 30 01 83 c1 01 83 fa 10 75 ec 83 c3 10 81 fb ?? ?? ?? ?? 75 d0}  //weight: 1, accuracy: Low
        $x_1_7 = {80 7b ff 3f 74 06 c6 03 26 83 c3 01}  //weight: 1, accuracy: High
        $x_2_8 = {83 f8 04 be 01 00 00 00 77 f6 ff 24 85 ?? ?? ?? ?? 8d 45 f3 b9 7c 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_F_144772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.F!dll"
        threat_id = "144772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 56 56 8d 45 fc 50 89 75 fc ff 15 ?? ?? 00 10 85 c0 74 16 56 56 68 ?? ?? 00 10 68 ?? ?? 00 10 56 e8 ?? ?? ?? ?? 85 c0 74 0d 68 ?? ?? ?? ?? ff 15 ?? ?? 00 10 eb c9 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_H_146841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.H!dll"
        threat_id = "146841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {99 ef 54 12 c6 67 ff 5f 45 90 78 90 f5 34 98 11 f1 9b 20 62 fc 48 d0}  //weight: 1, accuracy: High
        $x_1_3 = {55 89 e5 83 ec 18 8d 45 ff c6 45 ff 00 89 04 24 e8 ?? ?? ?? ?? 83 ec 04 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_L_148111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.L"
        threat_id = "148111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 da 31 c3 31 c0 81 fb ?? ?? ?? ?? 0f 93 c0 69 c0 00 c7 44 24 ?? ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {85 f6 ba 39 00 00 00 74 0b b8 39 00 00 00 31 d2 f7 f6}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {30 01 83 c1 01 83 fa 10 75 ec 83 c3 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Oficla_M_148130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.M"
        threat_id = "148130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f6 78 c6 45 f7 00 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 00 8d 45 f3 89 44 24 04}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0c 02 40 83 f8 10 75 f1 83 c2 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_M_148130_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.M"
        threat_id = "148130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 53 04 8d 93 ?? 01 00 00 83 ec 08 89 14 24 ff d0 83 e8 01 83 ec 04 83 f8 01 76 22}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 01 00 00 00 83 ec 08 8d 76 00 0f b6 83 ?? ?? ?? ?? 83 c3 01 89 7c 24 04 88 45 f2 8d 04 16 89 04 24 ff 15 ?? ?? ?? ?? 89 da 83 ec 08 83 fb 50 75 d9}  //weight: 1, accuracy: Low
        $x_1_3 = {ef 54 12 c6 67 ?? 5f 45 90 78 90 f5 34 98 11}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6e 74 72 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Oficla_N_148799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.N"
        threat_id = "148799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 30 34 64 25 30 34 64 30 30 30 31 00}  //weight: 1, accuracy: High
        $x_2_3 = {c7 04 24 04 01 00 00 04 00 89 ?? 24 04}  //weight: 2, accuracy: Low
        $x_3_4 = {80 7b ff 3f 74 ?? c6 03 26 43 8b 17 83 3c d5 ?? ?? ?? ?? 05 74}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_O_148889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.O"
        threat_id = "148889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f4 64 c6 45 f5 25 (83|8d 44 49 03 8d 04 80 c1) 88 45 f6 c6 45 f7 00 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 ?? ?? ?? ?? 8d 45 f3 89 44 24 04}  //weight: 1, accuracy: Low
        $x_1_2 = {00 69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 30 30 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 0d 0a 0d 0a 00 50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 00 47 45 54 00 50 4f 53 54 00 50 55 54 00 48 45 41 44 00 43 4f 4e 4e 45 43 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_P_149166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.P"
        threat_id = "149166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/bb.php?v=" ascii //weight: 3
        $x_1_2 = "taskid:" ascii //weight: 1
        $x_1_3 = "runurl:" ascii //weight: 1
        $x_1_4 = "inetmib1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_Q_149334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.Q"
        threat_id = "149334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 01 80 f1 ?? 8b 5d ?? 88 0c 03 40 4a 75 ed}  //weight: 2, accuracy: Low
        $x_1_2 = "backurls:" ascii //weight: 1
        $x_1_3 = "runurl:" ascii //weight: 1
        $x_1_4 = "&tm=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_R_149335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.R"
        threat_id = "149335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7b ff 3f 74 04 c6 03 26}  //weight: 1, accuracy: High
        $x_1_2 = {30 0c 02 40 83 f8 10 75 f1 83 c2 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_S_149336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.S"
        threat_id = "149336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 30 01 83 c1 01 83 fa 10 75 ec 83 c3 10 81 fb ?? ?? ?? ?? 75 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 0b 83 c3 01 39 5f 18 76}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 74 72 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_T_149855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.T"
        threat_id = "149855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8d 55 ec b8 53 00 00 00 e8 ?? ?? ?? ?? ff 75 ec 8d 55 ?? b8 (59|6f) 00 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {8a 0c 03 80 f1 ?? 88 0c 03 40 4a 75 f3}  //weight: 10, accuracy: Low
        $x_10_3 = {8a 14 03 80 f2 0d 88 14 03 40 4e 75 f3}  //weight: 10, accuracy: High
        $x_10_4 = {8a 0c 13 80 f1 0d 88 0c 13 42 48 75 f3}  //weight: 10, accuracy: High
        $x_1_5 = {75 73 65 72 69 6e 69 74 78 78 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_V_152766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.V"
        threat_id = "152766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 44 c6 45 ?? 25 c6 45 ?? (75|78) c6 45 ?? 25 c6 45 ?? (75|78) c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {0d 00 00 00 80 ba ff e8 a4 35 89 d1 31 d2 f7 f1 81 c2 00 e1 f5 05 c6 45 ?? 25 c6 45 ?? 64 c6 45 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_AB_156268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.AB"
        threat_id = "156268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZQHVWETE\\Tketowqfa\\Ykpdsys UV\\EwrvgnaXgtsmqn\\Dkpnokqn" ascii //weight: 1
        $x_1_2 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_AC_156319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.AC"
        threat_id = "156319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 31 c0 8d 76 00 8b 14 c5 ?? ?? 00 10 89 14 c5 ?? ?? 00 10 8b 0c c5 ?? ?? 00 10 89 0c c5 ?? ?? 00 10 40 85 d2 75 df c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_AE_156798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.AE"
        threat_id = "156798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 bd f4 fe ff ff 61 63 73 2e 74 28}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f6 78 c6 45 f5 25 c6 45 f4 75 c6 45 f3 25 c6 45 f7 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 83 94 01 00 00 33 83 96 01 00 00 0d 00 00 00 80}  //weight: 1, accuracy: High
        $x_1_4 = {8b 14 87 01 da 80 3a 47 75 ea 80 7a 03 50 75 e4 80 7a 07 41 75 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Oficla_AG_157466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.AG"
        threat_id = "157466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 bf a2 1a 50 81 f1 ff a2 1a 50 51 b9 b3 a1 ca 3b 81 f1 b3 b1 ca 3b 51 b9 37 0f 00 00 51}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 18 00 00 00 8b 40 34 83 f8 06 74 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = "fuck av" ascii //weight: 1
        $x_1_4 = "BitDefender 10" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Oficla_AI_159405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.AI"
        threat_id = "159405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 62 67 68 65 6c 70 2e 64 6c 6c 00 [0-4] 73 62 69 65 64 6c 6c 2e 64 6c 6c 00}  //weight: 2, accuracy: Low
        $x_2_2 = "img.php?v=1&id=" ascii //weight: 2
        $x_2_3 = {7a 65 6e 74 6f 77 6f 72 6c 64 5f 0a 00 5f 64 61 64 61 00}  //weight: 2, accuracy: Low
        $x_1_4 = {6f 6e 6c 69 6e 65 2e 77 65 73 74 70 61 63 2e 63 6f 6d 2e 61 75 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 69 6e 61 6e 7a 70 6f 72 74 61 6c 2e 66 69 64 75 63 69 61 2e 64 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {69 62 61 6e 6b 2e 61 6c 66 61 62 61 6e 6b 2e 72 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Oficla_AK_164091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oficla.AK"
        threat_id = "164091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ftp://%s:%s@%s" ascii //weight: 1
        $x_1_2 = "\\smdata.dat" ascii //weight: 1
        $x_1_3 = {0f be 00 83 f8 48 75 32 8b ?? ?? ?? ?? ?? 0f be 40 03 83 f8 74 75 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

