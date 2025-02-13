rule Backdoor_Win32_Escad_E_2147706488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.E!dha"
        threat_id = "2147706488"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 56 34 12 55 55 ?? f2 78 56 34 12 [0-32] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_E_2147706488_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.E!dha"
        threat_id = "2147706488"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 56 34 12 55 55 ?? f2 78 56 34 12 [0-32] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_G_2147706489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.G!dha"
        threat_id = "2147706489"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zz%d.bat" ascii //weight: 1
        $x_1_2 = {64 65 6c 20 22 [0-16] 69 66 20 65 78 69 73 74 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 63 75 2e 69 6e 66 [0-5] 52 65 67 69 73 74 65 72 [0-16] 6d 63 75 2e 64 6c 6c [0-16] 72 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_G_2147706489_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.G!dha"
        threat_id = "2147706489"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zz%d.bat" ascii //weight: 1
        $x_1_2 = {64 65 6c 20 22 [0-16] 69 66 20 65 78 69 73 74 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 63 75 2e 69 6e 66 [0-5] 52 65 67 69 73 74 65 72 [0-16] 6d 63 75 2e 64 6c 6c [0-16] 72 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_H_2147706490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.H!dha"
        threat_id = "2147706490"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 [0-5] 72 00 [0-5] 54 00 4d 00 50 00 25 00 64 00 2e 00 74 00 6d 00 70 00 [0-5] 73 00 [0-5] 3a 00 3a 00 5c 00 [0-5] 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%sd.e%sc \"%s > %s\" 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_H_2147706490_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.H!dha"
        threat_id = "2147706490"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 [0-5] 72 00 [0-5] 54 00 4d 00 50 00 25 00 64 00 2e 00 74 00 6d 00 70 00 [0-5] 73 00 [0-5] 3a 00 3a 00 5c 00 [0-5] 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%sd.e%sc \"%s > %s\" 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_J_2147706491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.J!dha"
        threat_id = "2147706491"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c net user Administrator %s" ascii //weight: 1
        $x_1_2 = "HaHaHa_%d%d%d%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_J_2147706491_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.J!dha"
        threat_id = "2147706491"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c net user Administrator %s" ascii //weight: 1
        $x_1_2 = "HaHaHa_%d%d%d%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_J_2147706491_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.J!dha"
        threat_id = "2147706491"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e0 08 33 c7 83 c1 04 c1 e0 08 33 c3 c1 e0 08 8b d0 33 d5 8b c2 89 91}  //weight: 10, accuracy: High
        $x_1_2 = "skinpfu.dat" ascii //weight: 1
        $x_1_3 = "skmsvxd.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_J_2147706491_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.J!dha"
        threat_id = "2147706491"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 78 00 6c 00 73 00 [0-6] 2e 00 77 00 72 00 69 00 [0-6] 2e 00 77 00 70 00 78 00 [0-6] 2e 00 77 00 70 00 64 00 [0-6] 2e 00 64 00 6f 00 63 00 6d 00 [0-6] 2e 00 64 00 6f 00 63 00 78 00 [0-6] 2e 00 64 00 6f 00 63 00 [0-6] 2e 00 63 00 61 00 62 00 [0-32] 25 00 63 00 3a 00 5c 00 [0-16] 5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_J_2147706491_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.J!dha"
        threat_id = "2147706491"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 0d 0a 64 65 6c 20 2f 61 20 22 25 73 22 [0-80] 4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 33 d2 be ?? ?? ?? ?? f7 f6 8a 82 ?? ?? ?? ?? 8a 91 ?? ?? ?? ?? 32 d0 88 91 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72 d8}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 16 2e f7 f9 c6 44 24 17 64 c6 44 24 18 6c c6 44 24 19 6c}  //weight: 1, accuracy: High
        $x_1_4 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 [0-5] 68 74 74 70 3a 2f 2f [0-96] 2e 65 78 65 [0-32] 53 74 61 72 74 49 6e 73 74 61 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Escad_K_2147706492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.K!dha"
        threat_id = "2147706492"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%smd.e%sc \"%s > %s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_K_2147706492_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.K!dha"
        threat_id = "2147706492"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%smd.e%sc \"%s > %s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_L_2147706493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.L!dha"
        threat_id = "2147706493"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 5c 25 49 36 34 75 5f 25 49 36 34 75 00}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /c \"%s > %s 2>&1" ascii //weight: 1
        $x_1_3 = "CMSAction::" ascii //weight: 1
        $x_1_4 = {6e 73 68 77 66 70 2e 6f 78 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 73 61 66 64 2e 61 78 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 63 63 62 61 73 65 2e 64 65 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Escad_L_2147706493_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.L!dha"
        threat_id = "2147706493"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 3c 07 4a 75 10 80 7c 07 01 45 75 09 c6 04 07 4d c6 44 07 01 5a}  //weight: 2, accuracy: High
        $x_2_2 = {8b 13 8b ca 8b f2 c1 e9 1d c1 ee 1e 8b fa 83 e1 01 83 e6 01 c1 ef 1f}  //weight: 2, accuracy: High
        $x_1_3 = {81 bc 24 0c 08 00 00 01 01 13 20 74 14 8b cb}  //weight: 1, accuracy: High
        $x_1_4 = "17121AB3-079E-4622-9315-44C0364C6123" ascii //weight: 1
        $x_1_5 = "127.0.0.1/top.gif" ascii //weight: 1
        $x_1_6 = "cmd.exe /c %s > \"%s\" 2>&1" ascii //weight: 1
        $x_1_7 = "1.2.7.f-" ascii //weight: 1
        $x_1_8 = {2e 47 65 2e 74 45 2e 78 69 20 74 43 2e 6f 64 20 65 50 2e 20 72 6f 63 20 65 2e 73 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {52 2e 20 65 2e 67 51 75 2e 2e 65 20 72 79 56 2e 61 6c 2e 75 65 45 20 78 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_L_2147706493_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.L!dha"
        threat_id = "2147706493"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 3c 07 4a 75 10 80 7c 07 01 45 75 09 c6 04 07 4d c6 44 07 01 5a}  //weight: 2, accuracy: High
        $x_2_2 = {8b 13 8b ca 8b f2 c1 e9 1d c1 ee 1e 8b fa 83 e1 01 83 e6 01 c1 ef 1f}  //weight: 2, accuracy: High
        $x_1_3 = {81 bc 24 0c 08 00 00 01 01 13 20 74 14 8b cb}  //weight: 1, accuracy: High
        $x_1_4 = "17121AB3-079E-4622-9315-44C0364C6123" ascii //weight: 1
        $x_1_5 = "127.0.0.1/top.gif" ascii //weight: 1
        $x_1_6 = "cmd.exe /c %s > \"%s\" 2>&1" ascii //weight: 1
        $x_1_7 = "1.2.7.f-" ascii //weight: 1
        $x_1_8 = {2e 47 65 2e 74 45 2e 78 69 20 74 43 2e 6f 64 20 65 50 2e 20 72 6f 63 20 65 2e 73 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {52 2e 20 65 2e 67 51 75 2e 2e 65 20 72 79 56 2e 61 6c 2e 75 65 45 20 78 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_M_2147706494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.M!dha"
        threat_id = "2147706494"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\"" ascii //weight: 1
        $x_1_2 = "*****[Listen Port %d] -" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_M_2147706494_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.M!dha"
        threat_id = "2147706494"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\"" ascii //weight: 1
        $x_1_2 = "*****[Listen Port %d] -" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_N_2147706495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.N!dha"
        threat_id = "2147706495"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 a2 df 2d 99 2b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 13 41 ff c0 48 ff c2 34 ?? 88 42 ff 41 8b c0 48 3b c1 72 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 03 3c 2e 74 09 3c 20 74 05 88 07 48 ff c7 48 ff c3 80 3b 00 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_N_2147706495_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.N!dha"
        threat_id = "2147706495"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 a2 df 2d 99 2b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 13 41 ff c0 48 ff c2 34 ?? 88 42 ff 41 8b c0 48 3b c1 72 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 03 3c 2e 74 09 3c 20 74 05 88 07 48 ff c7 48 ff c3 80 3b 00 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_O_2147706496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.O!dha"
        threat_id = "2147706496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 08 80 c2 ?? 80 f2 ?? 88 14 08 40 3b c6 7c ef}  //weight: 2, accuracy: Low
        $x_1_2 = {b8 2d 2d 2d 2d 8d}  //weight: 1, accuracy: High
        $x_1_3 = "=== %04d.%02d.%02d %02d:%02d:%02d ===" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_O_2147706496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.O!dha"
        threat_id = "2147706496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 08 80 c2 ?? 80 f2 ?? 88 14 08 40 3b c6 7c ef}  //weight: 2, accuracy: Low
        $x_1_2 = {b8 2d 2d 2d 2d 8d}  //weight: 1, accuracy: High
        $x_1_3 = "=== %04d.%02d.%02d %02d:%02d:%02d ===" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_P_2147706497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.P!dha"
        threat_id = "2147706497"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "#99E2428CCA4309C68AAF8C616EF3306582A64513E55C786A864BC83DAFE0C785" ascii //weight: 2
        $x_1_2 = "\\\\?\\ElRawDisk\\??\\" ascii //weight: 1
        $x_1_3 = " cl \"%s\"" ascii //weight: 1
        $x_1_4 = {64 65 6c 20 22 [0-16] 69 66 20 65 78 69 73 74 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = "%s%s.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_P_2147706497_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.P!dha"
        threat_id = "2147706497"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "#99E2428CCA4309C68AAF8C616EF3306582A64513E55C786A864BC83DAFE0C785" ascii //weight: 2
        $x_1_2 = "\\\\?\\ElRawDisk\\??\\" ascii //weight: 1
        $x_1_3 = " cl \"%s\"" ascii //weight: 1
        $x_1_4 = {64 65 6c 20 22 [0-16] 69 66 20 65 78 69 73 74 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = "%s%s.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_Q_2147706498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.Q!dha"
        threat_id = "2147706498"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 47 52 41 4e 54 3a 65 76 65 72 79 6f 6e 65 2c 46 55 4c 4c [0-16] 5c 5c 25 73 5c 73 68 61 72 65 64 24 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 [0-16] 2e 65 78 65 20 2f 6e 6f 64 65 3a 22 25 73 22 20 2f 75 73 65 72 3a 22 25 73 22 20 2f 70 61 73 73 77 6f 72 64 3a 22 25 73 22 20 50 52 4f 43 45 53 53 20 43 41 4c 4c 20 43 52 45 41 54 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_R_2147706499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.R!dha"
        threat_id = "2147706499"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "if exist %1 goto" ascii //weight: 1
        $x_1_2 = {25 73 6d 73 76 63 72 74 2e 62 61 74 [0-16] 4e 65 74 77 6f 72 6b 20 41 63 63 65 73 73 20 50 72 6f 74 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "wmplog21t.sqm" ascii //weight: 1
        $x_1_4 = {99 b9 ff 00 00 00 f7 f9 88 14 1f 43 83 fb ?? 72 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {99 b9 ff 00 00 00 f7 f9 46 88 54 37 ff 83 fe 76 72 e9}  //weight: 1, accuracy: High
        $x_1_6 = {57 33 db 50 c6 ?? ?? 6b c6 ?? ?? 65 c6 ?? ?? 72 c6 ?? ?? 6e c6 ?? ?? 65 c6 ?? ?? 6c c6 ?? ?? 33 c6 ?? ?? 32 c6 ?? ?? 2e c6 ?? ?? 64 c6 ?? ?? 6c c6 ?? ?? 6c}  //weight: 1, accuracy: Low
        $x_1_7 = {6b 65 72 6e c7 ?? ?? 6c 33 32 2e c7 ?? ?? 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Escad_F_2147706523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.F!dha"
        threat_id = "2147706523"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 72 65 67 6b 5d 00 00 5b 77 6f 77 36 34 5d 00 5b 6e 74 66 73 5d 00 00 5b 64 69 72 61 5d 00 00 5b 64 69 72 72 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 65 76 74 75 74 69 6c 2e 65 78 65 20 63 6c 20 22 25 73 22 20 2f 62 75 3a 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 66 78 25 69 25 69 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_F_2147706523_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.F!dha"
        threat_id = "2147706523"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 e2 34 80 c2 2d 88 54 24 10 8b d1 f7 da 1a d2 80 e2 37 80 c2 2d 88 54 24 11 8b d0 80 e2 02 f6 da 1a d2 80 e2 3b 80 c2 2d f7 d9 1a c9 24 04 80 e1 45 88 54 24 12 80 c1 2d}  //weight: 1, accuracy: High
        $x_1_2 = "%4d/%2d/%2d_%2d:%2d" ascii //weight: 1
        $x_1_3 = "%s %-20s %10lu %s" ascii //weight: 1
        $x_1_4 = {5f 71 75 69 74 00 00 00 5f 65 78 65 00 00 00 00 5f 70 75 74 00 00 00 00 5f 67 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Escad_F_2147706523_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.F!dha"
        threat_id = "2147706523"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 32 64 3a 25 32 64 00 25 73 20 25 2d 32 30 73 20 25 31 30 6c 75 20 25 73 0a 00 00 7c 00 00 00 5f 64 69 72 00 00 00 00 5f 67 65 74 00 00 00 00 5f 67 6f 74 00 00 00 00 5f 70 75 74 00 00 00 00 5f 65 78 65 00 00 00 00 5f 71 75 69 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {67 6f 00 00 74 69 00 00 73 68 00 00 66 73 00 00 74 73 00 00 64 6c 00 00 64 75 00 00 64 65 00 00 63 6d 00 00 63 75 00 00 65 78 00 00 25 2e 32 58}  //weight: 2, accuracy: High
        $x_1_3 = {8a 14 39 80 c2 03 0f b6 c2 83 f0 03 8b d0 c1 ea 03 c0 e0 05 0a d0 88 14 39 41 3b cb 7c e2}  //weight: 1, accuracy: High
        $x_1_4 = {d0 f9 ff ff 7a 69 1b df}  //weight: 1, accuracy: High
        $x_1_5 = {d0 f9 ff ff 92 e0 7c a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_D_2147706526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.D!dha"
        threat_id = "2147706526"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f f7 d1 18 e8}  //weight: 1, accuracy: High
        $x_1_2 = {97 f1 6f c4 75}  //weight: 1, accuracy: High
        $x_2_3 = {5f 65 78 65 00 00 00 00 5f 70 75 74 00 00 00 00 5f 71 75 69 74 00 00 00 5f 67 6f 74 00 00 00 00 5f 67 65 74 00 00 00 00 5f 64 65 6c 00 00 00 00 5f 64 69 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Escad_A_2147706529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.A!dha"
        threat_id = "2147706529"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 04 17 8b fb 34 ?? 46 88 02 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b f1 72 e3}  //weight: 3, accuracy: Low
        $x_5_2 = {57 b9 14 00 00 00 33 c0 8b fe f3 ab 80 3a 00 74 15 8a 02 3c 2e 74 07 3c 20 74 03 88 06 46 8a 42 01 42 84 c0 75 eb}  //weight: 5, accuracy: High
        $x_2_3 = "%sc \"%s > %s\" 2>&1" wide //weight: 2
        $x_2_4 = {47 6c 6f 62 61 6c 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 54 72 61 63 69 6e 67 25 64 2e 25 64 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_AB_2147707532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.AB!dha"
        threat_id = "2147707532"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 73 00 5c 00 69 00 69 00 73 00 73 00 76 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /c net stop MSExchangeIS /y" ascii //weight: 1
        $x_1_3 = "ElRawDisk\\??\\" ascii //weight: 1
        $x_1_4 = "cmd.exe /c net stop termservice /y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Escad_AA_2147707533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.AA!dha"
        threat_id = "2147707533"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 65 74 5f 76 65 72 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /c wmic.exe /node:\"%s\" /user:\"%s\" /password:\"%s\" PROCESS CALL CREATE" ascii //weight: 1
        $x_1_3 = {52 61 73 53 65 63 72 75 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 67 66 78 74 72 61 79 65 78 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Escad_AC_2147707534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.AC!dha"
        threat_id = "2147707534"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RSRC_HTML" ascii //weight: 2
        $x_2_2 = "RSRC_JPG" ascii //weight: 2
        $x_2_3 = "RSRC_WAV" ascii //weight: 2
        $x_5_4 = {8a 0c 18 80 f1 63 88 0c 18 8b 4d 00 40 3b c1 72 ef}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_AD_2147707536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.AD!dha"
        threat_id = "2147707536"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 5c 70 6d 2a 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 67 66 78 63 6f 6e 66 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 69 6e 6d 73 6e 33 32 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 64 2e 65 25 73 63 20 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Escad_S_2147707754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.S!dha"
        threat_id = "2147707754"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 17 8b fb 34 ?? 46 88 02 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b f1 72 e3}  //weight: 1, accuracy: Low
        $x_2_2 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\"" ascii //weight: 2
        $x_1_3 = "%smd.ex%sc \"%s > %s\"" ascii //weight: 1
        $x_1_4 = "Create P2P Thread" ascii //weight: 1
        $x_1_5 = {64 65 6c 20 22 [0-16] 69 66 20 65 78 69 73 74 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Escad_S_2147707754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Escad.S!dha"
        threat_id = "2147707754"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 73 00 64 00 2e 00 65 00 25 00 73 00 63 00 20 00 22 00 25 00 73 00 20 00 3e 00 20 00 25 00 73 00 22 00 20 00 32 00 3e 00 26 00 31 00 [0-16] 63 00 6d 00 [0-16] 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%sd.e%sc \"%s > %s\" 2>&1" wide //weight: 1
        $x_1_3 = "%smd.ex%sc \"%s > %s\" 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

