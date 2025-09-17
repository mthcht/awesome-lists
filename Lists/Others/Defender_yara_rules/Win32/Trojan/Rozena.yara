rule Trojan_Win32_Rozena_D_2147719741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.D!bit"
        threat_id = "2147719741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell -window hidden -EncodedCommand " wide //weight: 10
        $x_1_2 = {70 73 68 63 6d 64 00 43 4d 44 00 73 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 01 00 00 70 28 02 00 00 06 26 2a}  //weight: 1, accuracy: High
        $x_2_4 = "JABiAFUAaABuACAAPQAgACcAJABSAEgAUgAgAD0AIAAnACcAWwBEAGwAbABJAG0AcABvAHIAdAAo" wide //weight: 2
        $x_1_5 = "WwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyAC4AZABsAGwAIgApAF0AcAB1AGIAbABpAGMA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rozena_E_2147725138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.E!bit"
        threat_id = "2147725138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call(0,(sc.length > 0x1000 ? sc.length : 0x1000), 0x1000, 0x40)" ascii //weight: 1
        $x_1_2 = "def g(ip,port)" ascii //weight: 1
        $x_1_3 = "def ij(sc)" ascii //weight: 1
        $x_1_4 = ".call(pt,sc,sc.length)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GM_2147754622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GM!MTB"
        threat_id = "2147754622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c0 02 1c 07 8a 14 07 86 14 1f 88 14 07 02 14 1f 8a 14 17 30 55 00 45 49 75}  //weight: 1, accuracy: High
        $x_1_2 = "DVIIIDa.m.DkcalDp.m.DviiiD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_V_2147754996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.V!MTB"
        threat_id = "2147754996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 85 06 00 8b 95}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d1 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_ALR_2147783203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.ALR!MTB"
        threat_id = "2147783203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba d3 4d 62 10 89 c8 f7 ea 89 d0 c1 f8 ?? 89 ca c1 fa ?? 29 d0 69 d0 [0-5] 89 c8 29 d0}  //weight: 1, accuracy: Low
        $x_1_2 = "notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GG_2147788922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GG!MTB"
        threat_id = "2147788922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 10 40 e0 8d 40 40 83 c1 40 0f 28 ca 66 0f ef c2 0f 11 40 a0 0f 10 40 b0 66 0f ef c2 0f 11 40 b0 0f 10 40 c0 66 0f ef c2 0f 11 40 c0 0f 10 40 d0 66 0f ef c8 0f 11 48 d0 3b ca 72 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_SIB_2147798506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.SIB!MTB"
        threat_id = "2147798506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualAlloc" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "CreateThread" ascii //weight: 1
        $x_5_4 = "cmd.exe" ascii //weight: 5
        $x_10_5 = {8b 55 10 89 02 [0-10] 8b 45 ?? 3b 45 0c [0-16] 8b 45 02 8d 14 85 00 00 00 00 8b 45 08 01 d0 8b 00 0f b6 84 05 ?? ?? ?? ?? 0f be c8 8b 45 10 8b 10 8b 45 10 8b 00 89 4c 24 0c 89 54 24 08 c7 44 24 04 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 83 45 02 01 8b 45 02 3b 45 0c}  //weight: 10, accuracy: Low
        $x_10_6 = {58 31 c9 89 cb 6a 04 5a 43 ff 30 59 0f c9 31 d9 81 f9 ?? ?? ?? ?? 75 ?? 0f cb 31 c9 81 c1 ?? ?? ?? ?? 01 d0 31 18 e2 ?? 2d ?? ?? ?? ?? ff e0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rozena_RPF_2147815999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RPF!MTB"
        threat_id = "2147815999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 fc 30 04 31 8a 04 31 2a 45 fb 88 04 31 32 45 fa 88 04 31 02 45 f9 88 04 31 32 45 f8 88 04 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_AR_2147819191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.AR!MTB"
        threat_id = "2147819191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 d0 0f b6 10 8d 8d [0-4] 8b 45 d4 01 c8 0f b6 00 31 c2 8d 8d [0-4] 8b 45 d0 01 c8 88 10}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_XI_2147821700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.XI!MTB"
        threat_id = "2147821700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f0 f7 e5 d1 ea 83 e2 ?? 8d 04 52 89 f2 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 37 f7 d8 0f b6 84 06 ?? ?? ?? ?? 30 44 37 ?? 83 c6 ?? 39 f3 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_MA_2147822276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.MA!MTB"
        threat_id = "2147822276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8b 4d f0 8b 55 f0 88 14 08 8b 45 f0 89 45 ec ff 45 f0 eb}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 0c 11 31 c8 12 00 8b 45 ?? 8b 4d 0c 8b 55 [0-9] 8b 4d 10 8b 55 ?? 88 04 11 8b 45 ?? 89 45 ?? ff 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_MA_2147822276_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.MA!MTB"
        threat_id = "2147822276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "f0000000000000000000000000LJDELJDMLKAZDJDLKJZELK" ascii //weight: 2
        $x_2_2 = "Corkiest featureful ductileness" ascii //weight: 2
        $x_2_3 = "rtbEw6HIxpPJ+U0cvWXkuUEsxRuqSS9O" ascii //weight: 2
        $x_2_4 = "<<HTTP_FILENAME_PAYLOAD>>" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_BD_2147835440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.BD!MTB"
        threat_id = "2147835440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {30 01 8d 04 29 99 f7 7c 24 10 0f b6 82 [0-4] 30 41 01 8d 04 0b 99 8d 49 05 f7 7c 24 10 0f b6 82 [0-4] 30 41 fd 8d 04 0e 3d fa 00 00 00 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_BQ_2147837567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.BQ!MTB"
        threat_id = "2147837567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 24 18 00 00 eb 01 c7 44 24 1c 5c 52 b2 60 c7 44 24 20 31 d2 5a d5 c7 44 24 24 55 24 b1 e5 c7 44 24 28 46 01 7c 80 c7 44 24 2c 6c 00 00 d5 c7 44 24 30 9b 39 b4 b7 c7 44 24 34 b0 53 5e a0 c7 44 24 38 99 05 e3 32}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_RPA_2147837639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RPA!MTB"
        threat_id = "2147837639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c2 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_RDA_2147840148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RDA!MTB"
        threat_id = "2147840148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\CVV" ascii //weight: 1
        $x_1_2 = "\\svchost.exe" ascii //weight: 1
        $x_2_3 = {0f b6 75 10 8b 45 08 8b 4d f8 0f b6 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_SPA_2147841492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.SPA!MTB"
        threat_id = "2147841492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 95 79 fe ff ff 8b 45 e4 01 d0 0f b6 08 8b 45 e4 99 f7 7d e0 89 d0 0f b6 84 05 71 fe ff ff 31 c1 89 ca 8d 8d 79 fe ff ff 8b 45 e4 01 c8 88 10 83 45 e4 01 8b 45 e4 3d 62 01 00 00 76 c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_AZR_2147842274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.AZR!MTB"
        threat_id = "2147842274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 89 45 f8 33 f6 57 8d 45 fc 50 ff b6 ?? ?? ?? ?? ff d3 83 c6 04 83 c7 10 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_RK_2147843094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RK!MTB"
        threat_id = "2147843094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 68 30 c5 04 00 6a 00 ff 54 24 34}  //weight: 2, accuracy: High
        $x_2_2 = {8b 43 3c 89 45 f4 8b 43 38 05 08 c4 04 00 89 45 f0 8b 7d f0 8b 75 f4 b9 28 01 00 00 f3 a4}  //weight: 2, accuracy: High
        $x_1_3 = "shellcodeloder.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_EH_2147846234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.EH!MTB"
        threat_id = "2147846234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {d9 74 24 f4 5b 31 c9 66 b9 3b 55 31 53 1c 83 c3 04 03 53 18 e2}  //weight: 5, accuracy: High
        $x_5_2 = {d9 74 24 f4 5e 2b c9 66 b9 3b 55 83 ee fc 31 5e 13 03 5e 13 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Rozena_EH_2147846234_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.EH!MTB"
        threat_id = "2147846234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FRVWnZlbFV3V2tkVVJYZzJVVlJDVkZZeFNuTmFWekExV1ZkUmQxSnJ" ascii //weight: 1
        $x_1_2 = "udW5wYWNrKCUobTApKS5maXJzdCk=" ascii //weight: 1
        $x_1_3 = "CreateFileA" ascii //weight: 1
        $x_1_4 = "CreateMutexA" ascii //weight: 1
        $x_1_5 = "Zeus" ascii //weight: 1
        $x_1_6 = "apr_socket_recv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_MK_2147847390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.MK!MTB"
        threat_id = "2147847390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {85 c0 0f 48 c2 c1 f8 03 0f b6 84 05 ?? ?? ff ff 0f be d0 8b 45 ?? 83 e0 07 89 c1 d3 fa 89 d0 83 e0 01 85 c0}  //weight: 15, accuracy: Low
        $x_10_2 = {0f b6 00 0f be c0 34 ff 89 c2 8b 45 ?? 89 44 24 04 89 14 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_MK_2147847390_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.MK!MTB"
        threat_id = "2147847390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 46 18 8b 86 ?? ?? ?? ?? 2b 86 ?? ?? ?? ?? 2d 3a 67 02 00 01 86 ?? ?? ?? ?? 8b 4e 5c 8b 86 ?? ?? ?? ?? 88 1c 01 ff 46 5c 8b 86 ?? ?? ?? ?? 35 ?? ?? ?? ?? 29 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 83 f0 13 0f af 46 1c 89 46 1c 8b 86 ?? ?? ?? ?? 09 86 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = {31 0c 32 83 c6 ?? 8b 48 ?? 83 f1 ?? 29 88 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 83 f1 01 0f af 48 ?? 89 48 64 8b 88 ?? ?? ?? ?? 01 48 6c 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Rozena_RPY_2147850133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RPY!MTB"
        threat_id = "2147850133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 56 90 e9}  //weight: 1, accuracy: High
        $x_1_2 = {90 ff d5 89 c3 89 c7 e9}  //weight: 1, accuracy: High
        $x_1_3 = {ff d0 90 3c 06 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_RPY_2147850133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RPY!MTB"
        threat_id = "2147850133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 c7 44 24 38 5c 00 00 00 f7 f1 c7 44 24 34 74 00 00 00 c7 44 24 30 6f 00 00 00 c7 44 24 2c 6c 00 00 00 c7 44 24 28 73 00 00 00 c7 44 24 24 6c 00 00 00 c7 44 24 20 69 00 00 00 c7 44 24 1c 61 00 00 00 c7 44 24 18 6d 00 00 00 c7 44 24 14 5c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_ABS_2147851790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.ABS!MTB"
        threat_id = "2147851790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 6a 04 68 00 30 00 00 68 1f 03 00 00 6a 00 ff 15 ?? ?? ?? ?? 8b d8 ba 3d 06 00 00 8b f3 8a 8a ?? ?? ?? ?? 8d 76 01 83 ea 01 88 4e ff 79 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 50 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 8a 45 f8 83 c4 0c 88 04 1e 83 c7 02 46 81 fe 3d 06 00 00 72 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GPC_2147893319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GPC!MTB"
        threat_id = "2147893319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 44 24 30 80 36 27 89 5c 24 04 89 04 24 ff d7 83 ec 08 85 c0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GPA_2147896249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GPA!MTB"
        threat_id = "2147896249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 f1 56 88 8c 05 d4 fd ff ff 40 3d 24 02 00 00 72 e8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GPB_2147896645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GPB!MTB"
        threat_id = "2147896645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 f1 41 88 8c 05 9c f9 ff ff 40 3d 1e 03 00 00 72 e7}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_MKV_2147897915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.MKV!MTB"
        threat_id = "2147897915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c0 01 d0 8b 4c 24 14 8b 54 24 1c 8d 1c 11 89 04 24 e8 ?? ?? ?? ?? 88 03 8b 54 24 14 8b 44 24 1c 01 d0 0f b6 10 8b 4c 24 14 8b 44 24 1c 01 c8 83 f2 13 88 10 83 44 24 1c 01 8b 44 24 ?? d1 e8 39 44 24 1c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_SPXR_2147899985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.SPXR!MTB"
        threat_id = "2147899985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 8d 50 01 89 55 f4 0f b6 00 0f be c0 34 ff 89 c2 8b 45 e8 89 44 24 04 89 14 24 e8 ?? ?? ?? ?? 8b 45 f0 8d 50 ff 89 55 f0 85 c0 75 d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GPD_2147901694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GPD!MTB"
        threat_id = "2147901694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 fc c1 e0 05 33 45 fc 89 c2 8b 4d 08 8b 45 f8 01 c8 0f b6 00 0f b6 c0 31 d0 89 45 fc 83 45 f8 01 8b 45 f8 3b 45 0c 72 d6}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_GZC_2147902187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.GZC!MTB"
        threat_id = "2147902187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 88 84 04 ?? ?? ?? ?? 83 e2 1f 8a 54 14 2c 88 54 04 4c 40 3d ?? ?? ?? ?? ?? ?? 31 f6 31 ff 0f b6 84 34 ?? ?? ?? ?? 01 f8 02 44 34 4c 0f b6 f8 8d 84 24 ?? ?? ?? ?? 01 f0 46 89 44 24 04 8d 84 24 ?? ?? ?? ?? 01 f8 89 04 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_HNB_2147906810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.HNB!MTB"
        threat_id = "2147906810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 6c 70 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79}  //weight: 10, accuracy: High
        $x_10_2 = {5f 4e 6f 77 00 77 53 68 6f 77 57 69 6e 64 6f 77 00 49 6e 69 74 69 61 6c 69 7a 65 41 72 72 61 79 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}  //weight: 10, accuracy: High
        $x_1_3 = {00 50 52 4f 43 45 53 53 5f 42 41 53 49 43 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e 00 50 52 4f 43 45 53 53 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 55 53 50 45 4e 44 45 44 [0-37] 50 52 4f 43 45 53 53 42 41 53 49 43 49 4e 46 4f 52 4d 41 54 49 4f 4e}  //weight: 1, accuracy: Low
        $x_11_5 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 [0-146] 00 3f ?? 00 3a 00 5c 00 ?? 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 ?? 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 ?? 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rozena_HNC_2147907439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.HNC!MTB"
        threat_id = "2147907439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 43 6f 70 79 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 6f 70 5f 45 71 75 61 6c 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 65 73 75 6d 65 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_NR_2147908253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.NR!MTB"
        threat_id = "2147908253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 85 53 fe ff ff 89 04 24 e8 5a 5c 00 00 8d 95 4c fe ff ff}  //weight: 3, accuracy: High
        $x_3_2 = {89 54 24 0c c7 44 24 08 ?? ?? ?? ?? 89 44 24 04 8d 85 53 fe ff ff 89 04 24}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_MBYF_2147909971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.MBYF!MTB"
        threat_id = "2147909971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 2b f7 ba ?? ?? ?? ?? 8a 04 0e ?? ?? 8d 49 01 32 c3 ?? ?? 88 41 ff 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_RS_2147910274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.RS!MTB"
        threat_id = "2147910274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 9d 24 e7 ff ff 8d b5 24 e7 ff ff 80 f3 90 8b cf 2b f7 ba d5 18 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 8d 24 e7 ff ff 80 f1 90 8a 04 0e 8d 49 01 32 c3 88 41 ff}  //weight: 1, accuracy: High
        $x_1_3 = {8a 9d 24 e7 ff ff 8b cf 56 8d b5 24 e7 ff ff 80 f3 90 2b f7 ba d5 18 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 85 24 e7 ff ff 8a c8 80 f1 90 32 c1 88 06 8a 04 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Rozena_YAD_2147913540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.YAD!MTB"
        threat_id = "2147913540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e6 8b cd c1 ea 03 6b c2 19 2b c8 03 ce 8a 44 0c 20 32 86 00 70 50 00 46 88 47 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_ASJ_2147923174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.ASJ!MTB"
        threat_id = "2147923174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5c 24 18 31 ed eb ?? 0f b6 34 ?? 31 ?? 83 f6 ?? 87 de 88 1c 28 87 de 45}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 5c 24 1c 31 ed eb ?? 0f b6 34 ?? 31 ?? 83 f6 ?? 87 de 88 1c 28 87 de 45}  //weight: 2, accuracy: Low
        $x_3_3 = {83 ec 18 8b 05 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 04 24 89 4c 24 04 89 54 24 08 e8 ?? ?? ?? 00 8b 44 24 0c 8b 4c 24 10 8b 54 24 14 89 0d ?? ?? ?? 00 89 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 85 c9 75}  //weight: 3, accuracy: Low
        $x_1_4 = "main.DecryptXor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rozena_AMX_2147925766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.AMX!MTB"
        threat_id = "2147925766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 f7 ea 89 d0 c1 f8 05 89 ca c1 fa 1f 29 d0 69 d0 2c 01 00 00 89 c8 29 d0 89 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_EM_2147952439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.EM!MTB"
        threat_id = "2147952439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 00 0f be c0 34 ff 89 c2 8b 84 24 14 04 00 00 89 44 24 04 89 14 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rozena_SPDP_2147952442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozena.SPDP!MTB"
        threat_id = "2147952442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 50 01 89 94 24 ?? ?? ?? ?? 0f b6 00 0f be c0 34 ff 89 c2 8b 84 24 ?? ?? ?? ?? 89 44 24 04 89 14 24 e8 ae 10 00 00 8b 84 24 ?? ?? ?? ?? 8d 50 ff 89 94 24 ?? ?? ?? ?? 85 c0 75 bd}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

