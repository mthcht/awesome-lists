rule Trojan_Win32_Tibs_T_2147584944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.T"
        threat_id = "2147584944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 04 24 68 a0 0b 00 00 50}  //weight: 1, accuracy: High
        $x_1_2 = {61 6c 69 64 55 52 4c 00 00 00 52 65 76 6f 6b 65}  //weight: 1, accuracy: High
        $x_1_3 = {74 53 74 61 74 65 00 00 00 55 52 4c 4f 70 65 6e 42 6c 6f 63 6b 69 6e 67 53 74}  //weight: 1, accuracy: High
        $x_1_4 = {5f 63 6c 65 61 72 66 70 00 00 00 5f 63 6c 6f 73 65 00 00 00 5f 63 6f 6d 6d 69 74 00 00 00 5f 63}  //weight: 1, accuracy: High
        $x_1_5 = {5f 63 6f 6e 74 72 6f 6c 38 37 00 00 00 5f 63 6f 70 79 73 69 67 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 72 65 61 74 65 4d 75 74 65 78 41 00 00 00 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_P_2147593711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.P"
        threat_id = "2147593711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 01 01 00 d8 c1 c8 12}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 70 79 42 69 6e 64 49 6e 66 6f 00 00 00 47 65 74 43 6f 6d 70 6f 6e 65 6e 74 49 44 46 72 6f 6d 43 4c 53 53 50 45 43 00 00 00 49 73 4a 49 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_D_2147593743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!D"
        threat_id = "2147593743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "loaderbb.php?l=" ascii //weight: 3
        $x_2_2 = {67 73 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75}  //weight: 2, accuracy: High
        $x_2_3 = "&adv=" ascii //weight: 2
        $x_2_4 = {40 00 83 c6 03 66 89 06 58 83 c6 02 24 ff 50}  //weight: 2, accuracy: High
        $x_5_5 = "81.95.146.205" ascii //weight: 5
        $x_1_6 = "GlobalUserOffline" ascii //weight: 1
        $x_1_7 = "AbortSystemShutdownA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_S_2147594024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.S"
        threat_id = "2147594024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 6c 24 00 83 c4 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8d 5d 0c 8b 5c 23 00 8d 1c 03 8d 7d 08 8b 7c 27 00 8d 75 08 8b 74 26 00}  //weight: 1, accuracy: High
        $x_1_3 = {f7 d2 ff c2 29 d1 8d 04 01 50 8f 06 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c3 66 a5 66 a5 60 29 f3 61}  //weight: 1, accuracy: High
        $x_1_5 = {8d 4d fc 8b 4c 21 00 c9 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Tibs_U_2147594444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.U"
        threat_id = "2147594444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 fc 61 62}  //weight: 1, accuracy: High
        $x_1_2 = {81 45 08 34 12 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 72 69 76 65 00 00 00 53 48 46 72 65 65 4e 61 6d 65 4d 61 70 70 69 6e 67 73 00 00 00 53 48 47}  //weight: 1, accuracy: High
        $x_1_4 = {49 40 5a 00 00 00 73 74 72 65 72 72 6f 72 00 00 00 5f 43 49 61 73 69 6e 00 00 00 5f 43 49 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_DF_2147595633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.DF"
        threat_id = "2147595633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 55 72 6c 43 61 63 68 65 43 6f 6e 74 61 69 6e 65 72 41 00 00 00 46 69 6e 64 43 6c 6f 73 65 55}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 75 73 4c 6f 6f 6b 75 70 00 00 00 46 72 65 65 55 72 6c 43 61 63 68 65 53 70 61 63 65 57 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 57 69 64 65 6e 50 61 74 68 00 00 00 43 72 65 61 74 65 50 61 74 74 65 72 6e 42 72 75 73 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 81 c0 01 00 00 00 01 04 24 e8 ?? 00 00 00 bb e0 08 00 00 8d 1c 33 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_DG_2147595635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.DG"
        threat_id = "2147595635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 14 8d 1c 18 8b 75 10 89 f7 c9 c2 10 00 8d 05}  //weight: 1, accuracy: High
        $x_1_2 = {45 72 61 73 65 54 61 70 65 00 00 00 46 61 74 61 6c 45 78 69 74 00 47 44 49 33 32 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 57 69 6e 64 6f 77 41 00 00 00 43 72 65 61 74 65 50 6f 70 75 70 4d 65 6e 75 00 57 49 4e 49 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_DG_2147595635_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.DG"
        threat_id = "2147595635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 45 6e 68 4d 65 74 61 46 69 6c 65 00 00 00 45 78 74 46 6c 6f 6f 64 46 69 6c 6c 00 53 48 45 4c}  //weight: 1, accuracy: High
        $x_1_2 = {6f 70 65 72 74 69 65 73 00 00 00 53 48 41 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {44 72 61 77 49 6e 73 65 72 74 00 00 00 49 6d 61 67 65 4c 69 73 74 5f 43 6f 70 79 00 00 00 49 6d}  //weight: 1, accuracy: High
        $x_1_4 = {61 67 65 4c 69 73 74 5f 47 65 74 44 72 61 67 49 6d 61 67 65 00 47 44 49 33 32 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_5_5 = {8b 5d 14 8d 1c 03 8b 75 10 8b 7d 10 c9 c2 10 00 8d 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_DH_2147595636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.DH"
        threat_id = "2147595636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 4d 08 8b 09 f7 d9 01 4d 0c 8b 45 0c}  //weight: 2, accuracy: High
        $x_1_2 = {c9 c2 10 00 8d 05}  //weight: 1, accuracy: High
        $x_1_3 = {55 52 4c 00 00 00 49 73 4a 49 54 49 6e 50 72 6f}  //weight: 1, accuracy: High
        $x_1_4 = {66 6f 45 78 41 00 00 00 47 6f 70 68 65 72 46 69}  //weight: 1, accuracy: High
        $x_2_5 = {55 69 53 74 6f 70 44 65 62 75 67 67 69 6e 67 00 00 00 4c 64 72 45 6e 75 6d 52 65 73 6f 75 72 63}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_DI_2147595645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.DI"
        threat_id = "2147595645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!DOS is dead" ascii //weight: 1
        $x_1_2 = "avz.exe;" ascii //weight: 1
        $x_2_3 = "hlegehrivihbugPhSeDe" ascii //weight: 2
        $x_1_4 = "NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_5 = "EXPLODE 0" ascii //weight: 1
        $x_1_6 = "?wingdings" ascii //weight: 1
        $x_1_7 = "ORERt&" ascii //weight: 1
        $x_1_8 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_ED_2147596342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.ED"
        threat_id = "2147596342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 79 6e 00 00 00 5f 73 74 72 72 65 76 00 00 00 5f 73 74 72 73 65 74 00 00 00 5f 74 6f 6c 6f 77 65 72 00 00 00 5f 75 74 69 6d 65 00 00 00 5f 77}  //weight: 1, accuracy: High
        $x_1_2 = {4d 53 56 43 52 54 2e 44 4c 4c 00 55 53 45 52 33 32 2e 44 4c 4c 00 4b 45 52 4e 45 4c 33 32 2e 44}  //weight: 1, accuracy: High
        $x_1_3 = {72 61 77 53 74 61 74 65 41 00 00 00 45 6e 64 4d 65 6e 75 00 00 00 45 6e 64 50 61 69 6e 74 00 00 00 45 6e 75 6d 44 65 73 6b 74 6f 70 73 41 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EE_2147596343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EE"
        threat_id = "2147596343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 4c 4c 00 4d 53 56 43 52 54 2e 44 4c 4c 00 43 4f 4d 44 4c 47 33 32 2e 44 4c 4c 00 47 44 49 33}  //weight: 1, accuracy: High
        $x_1_2 = {5f 53 6f 72 74 00 00 00 44 72 61 77 53 74 61 74 75 73 54 65 78 74 41 00 00 00 46 6c 61 74 53 42}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 65 52 67 6e 00 00 00 43 72 65 61 74 65 49 43 41 00 00 00 43 72 65 61 74 65 52 65 63 74 52}  //weight: 1, accuracy: High
        $x_1_4 = {6c 6c 6f 63 00 00 00 5f 63 68 64 69 72 00 00 00 66 72 65 65 00 00 00 5f 43 49 6c 6f 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EI_2147596386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EI"
        threat_id = "2147596386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 63 6f 6d 63 74 6c 33 32 2e}  //weight: 1, accuracy: High
        $x_1_2 = {6f 6c 65 43 75 72 73 6f 72 49 6e 66 6f 00 00 00 47 65 74 43 6f 6e 73 6f 6c 65 43 50 00 00 00 43 72 65 61 74 65 54 61 70 65 50 61 72 74 69 74 69}  //weight: 1, accuracy: High
        $x_1_3 = {4c 64 72 53 65 74 44 6c 6c 4d 61 6e 69 66 65 73 74 50 72 6f 62 65 72 00 00 00 4c 64 72 53 68 75 74 64 6f 77 6e 54 68 72 65 61 64 00 00 00 4e 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_ET_2147597214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.ET"
        threat_id = "2147597214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 62 45 03 00 ?? 2d 61 45 03 00 83 ?? 01 75 f0 bf 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EW_2147597847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EW"
        threat_id = "2147597847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 d0 89 c1 c3 89 eb 81 c3 10 19 00 00 89 e8 c3 83 c4 04 89 e1 89 fc 50 89 cc 39 dd 7e af c3 56 89 ee ad}  //weight: 1, accuracy: High
        $x_1_2 = {83 c5 02 89 ef 83 c5 02 83 c7 02 89 f9 29 e9 89 ca 81 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EW_2147597847_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EW"
        threat_id = "2147597847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 61 64 41 6c 74 65 72 42 69 74 6d 61 70 00 00 00 50 61 67 65 53 65 74 75 70 44 6c 67 57 00 00 00 64 77 4f 4b 53 75 62 63 6c 61 73 73 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 6e 76 65 72 74 44 65 66 61 75 6c 74 4c 6f 63 61 6c 65 00 00 00 45 78 69 74 50 72 6f 63 65 73 73 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 47 65 74 43 50 49 6e 66 6f 45 78 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EV_2147597860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EV"
        threat_id = "2147597860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 89 ce c1 e9 ?? [0-9] 81 c1 ?? ?? ?? ?? 81 (c1|e9) ?? ?? ?? ?? [0-3] 8b 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EX_2147597885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EX"
        threat_id = "2147597885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 e8 c1 e2 1f 8d 44 02 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-2] 81 76 fc ?? ?? ?? ?? (49|83) [0-2] 75 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EY_2147598094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EY"
        threat_id = "2147598094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 c9 ff 41 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8d 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EZ_2147598192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EZ"
        threat_id = "2147598192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 31 c9 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8d 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FA_2147598193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FA"
        threat_id = "2147598193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce b9 00 00 00 00 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8d 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FB_2147598256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FB"
        threat_id = "2147598256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 cd ff 83 ed ?? 89 ea (08|84) d2 75 03 83 c0 02 [0-2] 09 (ed|d5) 75 ?? bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FC_2147598320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FC"
        threat_id = "2147598320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 ed 4d 83 ed ?? 89 ea 08 d2 75 03 83 c0 02 89 e9 09 cd 75 ee bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FD_2147598396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FD"
        threat_id = "2147598396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c5 83 ed ?? 83 ed ?? 66 09 ed [0-1] 74 05 05 00 02 00 00 89 ea 09 ea [0-1] 75 ?? bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FE_2147598536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FE"
        threat_id = "2147598536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 81 f9 3e 04}  //weight: 10, accuracy: High
        $x_1_2 = {c1 ca 18 c1 c2 08}  //weight: 1, accuracy: High
        $x_1_3 = {8d 6c 20 00 83 ed 02 (e9|83)}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 6c 20 00 83 c5 fe (e9|83)}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c5 fe 83 c5 fd (e9|66)}  //weight: 1, accuracy: Low
        $x_1_6 = {83 ed 02 83 c5 fd (e9|66)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_FF_2147598893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FF"
        threat_id = "2147598893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec e8 69 c0 ?? ?? ?? ?? bf ?? ?? ?? ?? 83 c9 ff (41|81) [0-5] 01 c7 [0-4] 96 ad 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_I_2147600115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.I"
        threat_id = "2147600115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 8d 64 24 04 e8 92 00 00 00 f7 db 29 df f7 db 01 de 89 c3 eb 15 bf 81 ?? 48 00 bb 59 f3 ff ff 81 c3 9e 0c 00 00 01 c7 89 f8 96 81 c3 e2 d9 0c 00 81 eb d9 d9 0c 00 58 b8 af 3e 00 00 e8 14 00 00 00 eb 23 55 89 e5 89 01 89 d8 8b 5d 08 6b db 03 43 c9 c2 04 00 89 da f7 da 01 d0 ba 45 00 00 00 83 f8 00 74 5c c3 68 cb df ff ff 56 e8 43 00 00 00 35 ?? ?? ?? ?? 51 89 f9 6a 01 e8 c3 ff ff ff 59 e8 83 ff ff ff b8 af 3e 00 00 31 d2 b9 09 00 00 00 f7 f1 f7 d8 8d 34 86 56 c3 31 d2 87 d1 5a 8d 1d f6 ?? 40 00 29 d2 8b 3b 52 ff d7 89 d0 e9 61 ff ff ff 55 89 e5 ad 83 ee 02 4e 4e c9 c2 08 00 f7 da 29 14 24 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 68 61 72 4e 65 78 74 41 00 00 00 43 6c 6f 73 65 43 6c 69 70 62 6f 61 72 64 00 00 00 43 72 65 61 74 65 44 65 73 6b 74 6f 70 41 00 00 00 43 72 65 61 74 65 50 6f 70 75 70 4d 65 6e 75 00 00 00 44 6c 67 44 69 72 4c 69 73 74 41 00 00 00 44 72 61 77 45 64 67 65 00 00 00 5f 43 49 70 6f 77 00 00 00 5f 47 65 74 6d 6f 6e 74 68 73 00 00 00 73 74 72 73 74 72 00 00 00 5f 5f 69 73 61 73 63 69 69 00 00 00 5f 5f 77 61 72 67 76 00 00 00 5f 61 6c 69 67 6e 65 64 5f 66 72 65 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 75 73 65 72 33 32 2e 64 6c 6c 00 6d 73 76 63 72 74 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FG_2147600210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FG"
        threat_id = "2147600210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e 00 00 31 d2 b9 09 00 00 00 f7 f1 f7 d8 8d 34 86 56 c3 31 d2 87 d1 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FH_2147600265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FH"
        threat_id = "2147600265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 87 d1 5a 8d 1d ?? ?? 40 00 29 d2 8b 3b 52 ff d7 69 c0 00 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FI_2147600280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FI"
        threat_id = "2147600280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 ca 83 c4 ?? 83 c4 ?? 8d 1d ?? ?? 40 00 [0-2] 6a ?? ff (13|d3) 69 c0 00 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FJ_2147600596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FJ"
        threat_id = "2147600596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 ca 83 c4 ?? 83 ec ?? 6a ?? ff 15 ?? ?? ?? ?? (69 c0 00 ?? ??|ba 00 00 01 00)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FL_2147601191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FL"
        threat_id = "2147601191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 d1 81 c4 ?? ?? ?? ?? 81 ec ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? (69 c0 00 ?? ??|ba 00 ?? ?? 00)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FM_2147601353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FM"
        threat_id = "2147601353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 d1 81 c4 ?? ?? ?? ?? 81 ec ?? ?? ?? ?? (68 ?? ?? ?? ??|6a ??) ff 15 ?? ?? ?? ?? (c1 e0|69 c0)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_G_2147601551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!G"
        threat_id = "2147601551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c7 f3 a4 61 83 c0 (04|05) ff e0 8b bd ?? ?? ?? ?? 03 bd ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 68 00 10 00 00 57 e8 8a 01 00 00 f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c7 f3 a4 61 (83 c0 ??|05 ?? ?? ?? ??) ff e0 60 8b bd ?? ?? ?? ?? 03 bd ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 68 00 10 00 00 57 e8 ?? ?? 00 00 f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_FN_2147601744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FN"
        threat_id = "2147601744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 d1 81 c4 ?? ?? ?? ?? 81 ec ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FO_2147601745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FO"
        threat_id = "2147601745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e0 8b 04 24 66 31 c0 8b 10 81 f2 ?? ?? ?? ?? 66 81 fa ?? ?? 74 07 2d 00 10 00 00 eb ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FP_2147601814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FP"
        threat_id = "2147601814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e0 8b 04 24 66 31 c0 89 c5 b8 ?? ?? ?? ?? 6a 00 ff 14 28 89 c2 69 d2 00 00 01 00 83 c4 04 29 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FR_2147601815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FR"
        threat_id = "2147601815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 10 [0-2] 69 ?? 00 00 01 00 09 00 [0-4] b8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-64] ad 35 ?? ?? ?? ?? ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FS_2147602382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FS"
        threat_id = "2147602382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 d1 58 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 00 00 00 01 6a 00 f7 64 24 04 83 c4 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FT_2147602641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FT"
        threat_id = "2147602641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 d1 58 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? [0-5] 81 (44|6c) 24 ?? 00 00 ?? ?? f7 64 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FU_2147603006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FU"
        threat_id = "2147603006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 12 5e c1 e0 18 b9 ?? ?? ?? ?? 81 0b 00 ba ?? ?? ?? ?? 81 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_FV_2147603008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FV"
        threat_id = "2147603008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 02 03 55 08 03 55 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-64] 69 c0 ?? ?? ?? ?? b9 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_H_2147603097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!H"
        threat_id = "2147603097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 07 c1 c0 07 0f af c0 69 c0 44 33 22 11 c1 c8 0f 69 c0 11 33 22 44 c1 c8 05 0f af c0 69 c0 13 13 00 00 ae e2 da}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 8b d8 81 eb ?? ?? ?? ?? 8d bb ?? ?? ?? ?? b9 ?? 00 00 00 81 37 ?? ?? ?? ?? af e2 f7 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {75 06 ff 80 b8 00 00 00 33 c0 c2 10 00 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 cc 64 8f 05 00 00 00 00 5f 8b 3c 24 b9 ?? ?? ?? ?? 81}  //weight: 1, accuracy: Low
        $x_1_4 = {76 24 ff 80 b8 00 00 00 eb 1c 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 00 64 8f 05 00 00 00 00 5f eb 06 61 33 c0 c2 10 00 8b 3c 24 b9 ?? ?? ?? ?? 81}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 7c 39 21 30 07 [0-1] fe 07 [0-1] c1 c0 03 [0-2] ae [0-1] e2 ?? 5f 4a 75}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 7c 39 2c 30 07 [0-1] fe 07 [0-1] c1 c0 03 [0-2] ae [0-1] e2 ?? 5f 4a 75}  //weight: 1, accuracy: Low
        $x_1_7 = {8d 7c 39 25 30 07 [0-1] fe 07 [0-1] c1 c0 03 [0-2] ae [0-1] e2 ?? 5f 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_FY_2147603158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FY"
        threat_id = "2147603158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f c8 b9 b9 34 ab 00 eb 00 81 e9 11 32 ab 00 68 ?? ?? ?? ?? 5a 01 c2 52 87 02 05 ?? ?? ?? ?? 6a 02 6a 02 e8 ?? ?? ?? ff e2 ee c3}  //weight: 1, accuracy: Low
        $x_1_2 = {bf c1 3e 5c f1 ff b4 0f 21 63 e4 0e e8 dc ff ff ff eb 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 89 e5 87 02 03 55 08 03 55 0c c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tibs_FZ_2147603171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.FZ"
        threat_id = "2147603171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fd ad 48 35 ?? ?? ?? ?? (87|89) 46 04 83 c6 03 e2 f1 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GA_2147603218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GA"
        threat_id = "2147603218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 02 03 55 08 03 55 0c [0-80] 0f c8 b9 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GB_2147603451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GB"
        threat_id = "2147603451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 0c 8b 4d 08 89 11 03 7d 10 03 75 10 c9 [0-64] 8b 3b 89 e3 53 ff d7 [0-32] 96 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GD_2147603682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GD"
        threat_id = "2147603682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 02 2b 55 08 2b 55 0c [0-68] 0f c8 b9 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GE_2147603683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GE"
        threat_id = "2147603683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 02 00 00 00 00 0f c1 02 2b 55 08 03 55 0c c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_EU_2147604697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.EU"
        threat_id = "2147604697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 89 ce b9 00 00 00 00 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? [0-1] 8b 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GF_2147605012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GF"
        threat_id = "2147605012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 00 66 ad 69 c0 00 00 01 00 66 ad c1 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GG_2147605148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GG"
        threat_id = "2147605148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f2 52 66 ad 69 c0 00 ?? ?? 00 [0-6] 66 ad c1 (c0|c8) ?? [0-2] c1 (c0|c8) ?? 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_I_2147606817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!I"
        threat_id = "2147606817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 53 55 e8 00 00 00 00 5d 81 ed ?? 2c 40 00 e8 e6 02 00 00 e8 b4 06 00 00 b8 00 00 00 00 85 c0 75 21 ff 85 ?? 2c 40 00 e8 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GI_2147607408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GI"
        threat_id = "2147607408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fd 8b 06 48 83 c6 fc 35 ?? ?? ?? ?? 50 8f 46 04 83 ee fd e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GJ_2147607724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GJ"
        threat_id = "2147607724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f2 52 66 ad 6b c0 ?? [0-6] 66 ad c1 (c0|c8) ?? [0-2] c1 (c0|c8) ?? 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GK_2147607725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GK"
        threat_id = "2147607725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ad 69 c0 00 ?? ?? 00 [0-6] 66 ad c1 (c0|c8) ?? [0-4] c1 (c0|c8) ?? 93 81 c3 1b 00 [0-12] (c3|c2 ?? ??) 66 ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GM_2147607863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GM"
        threat_id = "2147607863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d6 52 66 ad c1 e0 ?? 66 ad c1 c8 ?? c1 c0 ?? 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_GV_2147608153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.GV"
        threat_id = "2147608153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d6 52 ac 86 (c4|e0) ac 86 (c4|e0) c1 (e0|e8) ?? c1 (e0|e8)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HH_2147608857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HH"
        threat_id = "2147608857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 02 83 ea fd 42 83 c1 fe 83 e9 02 85 c9 10 00 [0-3] 68 ?? ?? 00 00 59 87 02 [0-3] 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HI_2147609145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HI"
        threat_id = "2147609145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 66 ad c1 e0 04 c1 e0 04 c1 e0 04 c1 e0 04 66 ad c1 c0 02 c1 c0 0b c1 c0 03 93 81 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HN_2147609826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HN"
        threat_id = "2147609826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8b 55 14 2b 55 10 42 4a 41 52 51 29 d2 52 52 ba ?? ?? ?? ?? ff 12 59 5a 85 d2 75 eb 03 4d 0c 03 4d 08 81 e9 [0-4] c9 c2 10 00}  //weight: 1, accuracy: Low
        $x_2_2 = {66 ad c1 e0 04 c1 e0 0c 66 ad c1 c0 02 c1 c0 0b c1 c0 03 93 81 c3 ?? ?? ?? ?? 89 d8 66 ab c1 c8 04 c1 c8 0c 66 ab e2 d8 eb 2b c1 e9 1f 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 ca b8 ?? ?? ?? ?? 96 81 c6 ?? ?? ?? ?? 89 f7 56 eb ab c3}  //weight: 2, accuracy: Low
        $x_2_3 = "URLOpenStreamA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_HO_2147610157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HO"
        threat_id = "2147610157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 58 01 df 03 14 06 03 (83 c7 14 83|83 ef ?? 81 ef ?? ?? ?? ??) 83 c7 0a 83 ef 0f 83 ef 05 e2 ab 50 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HP_2147610158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HP"
        threat_id = "2147610158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 5a 85 d2 75 4a 41 52 51 [0-1] (29|(??|?? ??|?? ?? ??|?? ?? ?? ??) 6a ?? 6a ??)}  //weight: 1, accuracy: Low
        $x_1_2 = {03 4d 0c 03 4d 08 81 e9}  //weight: 1, accuracy: High
        $x_2_3 = {03 4d 0c 03 4d 08 81 e9 01 ?? ?? ?? c9 06 00 (59 5a|5a 59) 85 d2 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_HQ_2147610892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HQ"
        threat_id = "2147610892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 cb c3 ad 35 ?? ?? ?? ?? ab e2 f7 c3 8b 44 24 ?? c1 e8 ?? c1 e8 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HS_2147610981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HS"
        threat_id = "2147610981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 02 83 ea (fe 42 42 83 c1 ff 83|ff 42 42 42 83 c1 fe 83) 09 c9 14 00 [0-3] 68 ?? ?? 00 00 59 87 02 [0-3] 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_LD_2147611233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.LD"
        threat_id = "2147611233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 5a 01 df (83 ef ??|81 ef ?? ?? ?? ??) 81 ef ?? ?? ?? ?? e2 (ab|(57|6a ??) e8 ?? ?? ?? ??) 52 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IE_2147611460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IE"
        threat_id = "2147611460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 61 63 6b 75 70 52 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 61 75 6c 74 49 6e 49 45 46 65 61 74 75 72 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 43 6c 61 73 73 46 69 6c 65 4f 72 4d 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 49 6e 74 65 72 6e 65 74 50 61 72 73 65 55 72 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 6d 61 67 65 4c 69 73 74 5f 44 72 61 67 45 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_10_6 = {50 15 01 00 3b ?? 74 08 c1 (00|2d|07) 02 e9 ee ff ff ff [0-2] 3b (c0|2d|ff) [0-2] 0f 8f d2 ff ff ff (b8|2d|bf) ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ?? c3 38 00 83 (c8|2d|cf) ff ?? 03 ?? 24 34 81 (c0|2d|c7) ?? ?? ?? ?? 81 (e8|2d|ef) ?? ?? ?? ?? 81 (c0|2d|c7) ?? ?? ?? ?? 81 (c0|2d|c7) ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 81 (c0|2d|c7) ?? ?? ?? ?? 81 (c0|2d|c7) ?? ?? ?? ?? ?? ?? 2b ?? ?? (b8|2d|bf)}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_IF_2147611601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IF"
        threat_id = "2147611601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 4d 0c 03 4d 08 81 e9}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 fe 8b 28 b9 ?? ?? ?? ?? ff 94 29 ?? ?? ?? ?? [0-3] 09 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IG_2147612105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IG"
        threat_id = "2147612105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 83 c0 01 8b 18 be ?? ?? ?? ?? ff 94 1e ?? ?? ?? ?? 61 b9 ?? ?? 00 00 c9 c2 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IH_2147612732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IH"
        threat_id = "2147612732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 18 be db ?? ?? ?? ff 94 ?? ?? ?? ?? ?? 61 b9 ?? ?? ?? ?? c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 05 ee 0f 00 81 f3 45 ee 0f 00 8d 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_II_2147612795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.II"
        threat_id = "2147612795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 38 85 c0 75 c1 e8 ?? c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c8 ff 05 88 25 f4 0f e8 58}  //weight: 1, accuracy: Low
        $x_1_3 = {81 f2 54 a4 00 00 66 81 fa 19 fe 74 ?? 2d ?? ?? ?? ?? 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_JAB_2147615356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JAB"
        threat_id = "2147615356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 d3 01 00 00 e8 89 01 00 00 e8 58 02 00 00 b8 00 00 00 00 85 c0 75 27 ff 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_L_2147615647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!L"
        threat_id = "2147615647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e3 06 c1 e3 0a 01 df 83 ef 04 81 ef 00 80 00 00 81 ef 00 80 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_M_2147615789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!M"
        threat_id = "2147615789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 05 59 f7 fa ff 05 e7 1a 05 00 b9 15 bb 41 00 8b 19 0f c1 5d fc bb 05 3e 1f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JAC_2147615820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JAC"
        threat_id = "2147615820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1111"
        strings_accuracy = "Low"
    strings:
        $x_1111_1 = {59 5a c1 e3 ?? c1 e3 ?? 8d 7c 1f ?? 81 ef ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? e2 c8 c3}  //weight: 1111, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_N_2147616016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!N"
        threat_id = "2147616016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = ".php?affid=%u" ascii //weight: 1
        $x_1_3 = "%s%s%stibs.jpg" ascii //weight: 1
        $x_1_4 = "?affid=%u&code1=%c%c%c%c" ascii //weight: 1
        $x_1_5 = "netsh firewall set allowedprogram '%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IK_2147616018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IK"
        threat_id = "2147616018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 19 0f c1 5d fc bb ?? ?? ?? ?? 81 f3 ?? ?? ?? ?? 8d 55 f4 52 53 50 56 ff 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_O_2147616257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!O"
        threat_id = "2147616257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 18 43 81 3b 72 73 72 63 74}  //weight: 3, accuracy: High
        $x_1_2 = {66 c7 45 fc 63 74 c6 45 fe 00 60 8d 45 ec 50}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 f0 56 69 72 74 c7 45 f4 75 61 6c 41}  //weight: 1, accuracy: High
        $x_1_4 = {55 89 e5 83 ec 20 c7 45 e0 56 69 72 74 c7 45 e4 75 61 6c 41}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 fc 00 00 00 00 60 8b 75 08 03 76 3c 0f b7 56 06 4a}  //weight: 1, accuracy: High
        $x_1_6 = {03 76 3c 0f b7 56 06 4a 0e 00 c7 85 ?? ?? ff ff 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_P_2147616268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!P"
        threat_id = "2147616268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c3 58 59 5a c1 e3 10 8d 7c 1f fc 81 ef 00 00 01 00 e2 d1 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_Q_2147616270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!Q"
        threat_id = "2147616270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c3 58 59 5a c1 e3 09 c1 e3 07 8d 7c 1f fc 81 ef 00 80 00 00 81 c7 00 80 ff ff e2 c5 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_R_2147616273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!R"
        threat_id = "2147616273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 8d 94 17 a1 22 00 00 81 (ea 1f b1|c2 e1 4e) 81 fa e1 4e 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d7 f3 0f 2d cf 09 c9 74 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HX_2147616330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HX"
        threat_id = "2147616330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c3 58 59 5a 69 db 00 00 01 00 01 df 83 ef 01 83 ef 01 83 ef 02 81 ef 00 70 00 00 81 ef 00 60 00 00 81 ef 00 30 00 00 e2 b7 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_HX_2147616330_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.HX"
        threat_id = "2147616330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 83 e8 03 29 c2 49 eb ?? 89 d7 85 c9 74 02 29 c9 81 c1 90 4c 00 00 e8 ?? ff ff ff 59 eb ?? e8 ?? ff ff ff 08 00 [0-2] c3 51 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_S_2147616355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!S"
        threat_id = "2147616355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 db 00 00 01 00 01 df 83 ef 01 83 ef 01 83 ef 02 81 ef 00 70 00 00 81 ef 00 60 00 00 81 ef 00 30 00 00 e2 b4 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IP_2147616601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IP"
        threat_id = "2147616601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 7f 81 fa 00 (90|90|a0) 00 00 7f 04 00 8b (90|90|15) 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 55 89 e5 83 ec 04 c7 45 fc ?? ?? ?? ?? c7 45 fc ?? ?? ?? ?? ab c9 c3 07 00 e8 ?? 00 00 00 e2}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 ff ba ?? ?? ?? ?? c1 c2 0b 00 b9 ?? ?? ?? ?? 81 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tibs_IQ_2147617656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IQ"
        threat_id = "2147617656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 d0 0f 6f 00 0f 7e c0 c9 c2}  //weight: 2, accuracy: High
        $x_1_2 = {0f 34 c3 8d 0d 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {cd 2b c3 8d 0d 00 00 00 00}  //weight: 1, accuracy: High
        $x_3_4 = {0f 6f 01 0f 7e 45 fc bb ?? ?? ?? ?? 81 f3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tibs_IS_2147618654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IS"
        threat_id = "2147618654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 cd 2b b9 ?? ?? ?? ?? 81 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 6e c0 0f 7e 07 83 c7 ?? 83 ef ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_IT_2147618655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IT"
        threat_id = "2147618655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 c9 ff 66 41 66 8b 11 66 81 f2 ?? ?? 66 81 fa ?? ?? 74 ?? 81 e9 ?? ?? ?? ?? 81 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 01 c2 8b 4d fc 89 d6 c9 c2 04 00 02 00 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_IU_2147619588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IU"
        threat_id = "2147619588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 cd 2c 74 ?? 8b 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {28 c0 c0 e4 07 31 db (80|80 78) 74 0c 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_IV_2147621115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IV"
        threat_id = "2147621115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 7e 26 66 0f 7e e0 83 c6 02 83 c6 02 f8 73 ?? 50 f3 0f 7e 14 24 58 66 0f 7e 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IW_2147622122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IW"
        threat_id = "2147622122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 7e 26 89 e8 66 0f 7e e0 83 c6 02 83 c6 02 f8 73 ?? 50 f3 0f 7e 0c 24 fc 58 66 0f 7e 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_T_2147622493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!T"
        threat_id = "2147622493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 6e c0 0f 6f c8 0f 7e c8 48 83 f8 00 75 f1 8b 04 24 83 c4 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IY_2147623194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IY"
        threat_id = "2147623194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "81.177.26.27" ascii //weight: 1
        $x_1_2 = {50 ff 75 10 be ?? ?? 40 00 56 e8 ?? ?? ?? ?? 59 50 56 53 ff 15 ?? ?? 40 00 ff 15 ?? ?? 40 00 53 ff d7 ff 75 fc ff d7 5b ff 75 f8 ff d7 5f 5e c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_IZ_2147623195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.IZ"
        threat_id = "2147623195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess" ascii //weight: 1
        $x_1_2 = "%s, %d %s %04d %02d:%02d:%02d %c%02d%02d" ascii //weight: 1
        $x_1_3 = {6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 8b f8 83 ff ff 74 ?? ff 75 08 e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 6a 19 66 c7 45 f0 02 00 e8 ?? ?? ?? ?? 66 89 45 f2 8b 46 0c 8b 00 8b 00 89 45 f4 6a 10 8d 45 f0 50 57 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JB_2147623777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JB"
        threat_id = "2147623777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 25 00 f0 92 8a 02 34 ?? 3c ?? e8 ?? ?? ?? ?? 75 ?? 81 c2 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3a 4d 74 08 81 ea 00 10 00 00 eb f3 83 c4 04 56 57 53 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_JD_2147629104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JD"
        threat_id = "2147629104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 f4 52 51 6a 04 57 ff 55 fc 14 00 0f 6f ?? 89 c1 0f 7e ?? fc b9 ?? ?? ?? ?? 81 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JE_2147629837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JE"
        threat_id = "2147629837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0d 40 02 fe 7f 69 c9 ?? ?? ?? ?? 01 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JF_2147634464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JF"
        threat_id = "2147634464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e da 66 0f 7e d9 0a 00 ff 55 e4 c9 c3 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 6e c8 0f 54 c1 66 0f 7e c2 8a 02 34 ?? 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_JG_2147634562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JG"
        threat_id = "2147634562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 d6 5a 28 d2 8a 42 01 34 ?? 3c}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 6e 04 24 66 0f 7e c2 89 d7 89 fe 89 cb e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_JG_2147634562_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JG"
        threat_id = "2147634562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff ff d1 c9 c3 ba ?? ?? ?? ?? 66 0f 6e ?? 66 0f 7e ?? [0-2] 31 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 6e c8 66 0f 54 c1 66 0f 7e c2 8a 02 34 ?? 3c ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_JH_2147636372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JH"
        threat_id = "2147636372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 be 46 00 f2 0f f0 [0-2] 66 0f d0 d8 6a 00 6a 00 66 0f d6 1c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 d4 20 55 26 02 c7 45 d8 10 44 65 22 c7 45 dc 56 69 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JI_2147636397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JI"
        threat_id = "2147636397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 6e e2 66 0f 7e e1 01 c1 31 d2 6a 7b db 1c 24 58 3d 00 00 00 80 75}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ed 6b c6 45 ee 00 c6 45 ef 65 c6 45 f0 00 c6 45 f1 72 c6 45 f2 00 c6 45 f3 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JJ_2147636398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JJ"
        threat_id = "2147636398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 ff ff 00 00 0f ae 14 24 58 6a 00 0f ae 1c 24 58 40 8d b0}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ec 6b c6 45 ed 00 c6 45 ee 65 c6 45 ef 00 c6 45 f0 72 c6 45 f1 00 c6 45 f2 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JK_2147636450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JK"
        threat_id = "2147636450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 ff 75 08 ff d1 c9 c2 04 00 ba ?? ?? ?? ?? (66 0f 6e ?? 66 0f 7e ??|89 d1) 31 d2 41 42 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JL_2147637263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JL"
        threat_id = "2147637263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e e2 66 0f 7e e1 01 c1 31 d2 6a ?? db 1c 24 58 3d 00 00 00 80 75 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {68 ff ff 00 00 0f ae 14 24 58 6a 00 0f ae 1c 24 58 40}  //weight: 1, accuracy: High
        $x_1_3 = {83 e2 fe 69 c2 00 10 00 00 59 5a 66 0f 12 12 66 0f 7e d2 01 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tibs_LE_2147637377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.LE"
        threat_id = "2147637377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 61 6e 64 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 c7 45 ?? 63 74 45 78 c6 45 ?? 00 c6 45 ?? 6b c6 45 ?? 00 c6 45 ?? 45 c6 45 ?? 00 c6 45 ?? 52 c6 45 ?? 00 c6 45 ?? 6e c6 45 ?? 00 c6 45 ?? 65 c6 45 ?? 00 c6 45 ?? 6c c6 45 ?? 00 c6 45 ?? 33 c6 45 ?? 00 c6 45 ?? 32 c6 45 ?? 00 c6 45 ?? 00 c6 45 ?? 00 ?? 8d 55 ?? c7 ?? 56 69 72 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JM_2147637588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JM"
        threat_id = "2147637588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 d0 0f 6e c0 0f 6e 0e 0f 73 f1 20 0f eb c8 f3 0f d6 c1 0f 13 07 81 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_JN_2147638757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JN"
        threat_id = "2147638757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 02 56 69 72 74}  //weight: 1, accuracy: High
        $x_1_2 = {8d 90 a0 00 00 00 8b 02 8b 00 8d 50 08}  //weight: 1, accuracy: High
        $x_1_3 = {8b 10 81 c2 45 23 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 43 04 8b 44 04 11 39 d8 74 03 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_5 = {87 ca 31 d2 41 42 81 fa ?? ?? ?? ?? 75 f6 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {89 d1 01 c1 31 d2 83 c1 01 83 c2 01 81 fa ?? ?? ?? ?? 75 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tibs_JP_2147646378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.JP"
        threat_id = "2147646378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 11 60 83 ec 08 0f 01 0c 24 58 07 00 83 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tibs_B_90215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tibs.gen!B"
        threat_id = "90215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tibsloader" ascii //weight: 1
        $x_2_2 = "%s/%s?v=%s&act=%" ascii //weight: 2
        $x_2_3 = "&aid=%s&skid=%s" ascii //weight: 2
        $x_1_4 = "%s:%04d%02d%02d%" ascii //weight: 1
        $x_1_5 = "c=%s&cid=%d" ascii //weight: 1
        $x_1_6 = "TIBS%s" ascii //weight: 1
        $x_3_7 = "cgi-bin/%s?prog=ldr&ver=%s&code=%d&info=%s" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

