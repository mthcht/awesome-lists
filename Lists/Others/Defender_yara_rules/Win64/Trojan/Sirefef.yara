rule Trojan_Win64_Sirefef_A_2147646728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.A"
        threat_id = "2147646728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 30 63 6e 63 74 48 89 7e 28}  //weight: 1, accuracy: High
        $x_1_2 = {48 b9 47 42 ca 72 2e 8e 40 42 45 32 d2 48 33 c1 48 b9}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 48 83 ec 20 ff d0 48 83 4c}  //weight: 1, accuracy: High
        $x_1_4 = "stat.php?w=%u&i=%s&a=%u" ascii //weight: 1
        $x_1_5 = "x64\\release\\droper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Sirefef_A_2147646728_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.A"
        threat_id = "2147646728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 30 63 6e 63 74 48 89 7e 28}  //weight: 1, accuracy: High
        $x_1_2 = {48 b9 47 42 ca 72 2e 8e 40 42 45 32 d2 48 33 c1 48 b9}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 48 83 ec 20 ff d0 48 83 4c}  //weight: 1, accuracy: High
        $x_1_4 = "stat.php?w=%u&i=%s&a=%u" ascii //weight: 1
        $x_1_5 = "x64\\release\\droper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Sirefef_B_2147646729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.B"
        threat_id = "2147646729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 49 8b ?? 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 10 00 00 24 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "x64\\release\\InCSRSS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_B_2147646729_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.B"
        threat_id = "2147646729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 49 8b ?? 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 10 00 00 24 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "x64\\release\\InCSRSS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_C_2147651095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.C"
        threat_id = "2147651095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 81 f8 63 6e 63 74}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 45 08 78 56 4f 23 48 89 45}  //weight: 1, accuracy: High
        $x_1_3 = {41 bb 8a de 67 35 49 03 d1 0f be 0a 45 6b db 21 48 ff c2 44 33 d9}  //weight: 1, accuracy: High
        $x_1_4 = "stat2.php?w=%u&i=%s&a=" ascii //weight: 1
        $x_1_5 = "x64\\release\\shell" ascii //weight: 1
        $x_3_6 = {74 18 8b 12 81 ea 0b 01 00 00 74 4f 83 fa 01 75 09 48 8b 49 10 e8 5a fe ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_C_2147651095_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.C"
        threat_id = "2147651095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 81 f8 63 6e 63 74}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 45 08 78 56 4f 23 48 89 45}  //weight: 1, accuracy: High
        $x_1_3 = {41 bb 8a de 67 35 49 03 d1 0f be 0a 45 6b db 21 48 ff c2 44 33 d9}  //weight: 1, accuracy: High
        $x_1_4 = "stat2.php?w=%u&i=%s&a=" ascii //weight: 1
        $x_1_5 = "x64\\release\\shell" ascii //weight: 1
        $x_3_6 = {74 18 8b 12 81 ea 0b 01 00 00 74 4f 83 fa 01 75 09 48 8b 49 10 e8 5a fe ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_D_2147651096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.D"
        threat_id = "2147651096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 9c 24 b8 00 00 00 44 33 9c 24 bc 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 b0 3b 48 8b d0 2b c8 e8 ?? ?? ?? ?? 48 85 c0 74 24 48 8b d0 48 2b d3 48 83 fa 40}  //weight: 1, accuracy: Low
        $x_2_3 = {68 69 74 3f 74 35 32 2e 36 3b 72 68 74 74 70 3a 2f 2f 25 75 3b 73 25 75 2a 25 75 2a 25 75 3b 75 2f 25 75 3b 30 2e 25 75 25 75 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_D_2147651096_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.D"
        threat_id = "2147651096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 9c 24 b8 00 00 00 44 33 9c 24 bc 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 b0 3b 48 8b d0 2b c8 e8 ?? ?? ?? ?? 48 85 c0 74 24 48 8b d0 48 2b d3 48 83 fa 40}  //weight: 1, accuracy: Low
        $x_2_3 = {68 69 74 3f 74 35 32 2e 36 3b 72 68 74 74 70 3a 2f 2f 25 75 3b 73 25 75 2a 25 75 2a 25 75 3b 75 2f 25 75 3b 30 2e 25 75 25 75 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_E_2147651097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.E"
        threat_id = "2147651097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = "click_shell.dll" ascii //weight: 1
        $x_1_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 3d 00 00 00 16 00 18 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_E_2147651097_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.E"
        threat_id = "2147651097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = "click_shell.dll" ascii //weight: 1
        $x_1_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 3d 00 00 00 16 00 18 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_F_2147651196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.F"
        threat_id = "2147651196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 4d 54 48 8b f8 49 8b f4 f3 a4 0f b7 55 14 44 0f b7 4d 06 4c 8d 44 2a 24 41 8b 00 41 8b 48 fc 49 83 c0 28 41 83 c1 ff 4a 8d 34 20 48 8d 3c 18 f3 a4 75 e5}  //weight: 3, accuracy: High
        $x_1_2 = "x64\\release\\INBR64" ascii //weight: 1
        $x_1_3 = "\\U\\%08x.@" wide //weight: 1
        $x_1_4 = "%sU\\%08x.@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_F_2147651196_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.F"
        threat_id = "2147651196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d 54 48 8b f8 49 8b f4 f3 a4 0f b7 55 14 44 0f b7 4d 06 4c 8d 44 2a 24 41 8b 00 41 8b 48 fc 49 83 c0 28 41 83 c1 ff 4a 8d 34 20 48 8d 3c 18 f3 a4 75 e5}  //weight: 2, accuracy: High
        $x_1_2 = "x64\\release\\INBR64" ascii //weight: 1
        $x_1_3 = "\\U\\%08x.@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_G_2147651448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.G"
        threat_id = "2147651448"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 49 8b ?? 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = {ff e0 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00 41 51}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 43 53 52 53 53 2e 64 6c 6c 00 43 6f 6e 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_G_2147651448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.G"
        threat_id = "2147651448"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 49 8b ?? 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = {ff e0 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00 41 51}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 43 53 52 53 53 2e 64 6c 6c 00 43 6f 6e 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_H_2147651603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.H"
        threat_id = "2147651603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 83 ef 08 ff ce 48 8b 1f 48 83 27 00 48 85 db}  //weight: 5, accuracy: High
        $x_1_2 = {41 81 f8 64 69 73 63}  //weight: 1, accuracy: High
        $x_1_3 = {41 81 f8 72 65 63 76}  //weight: 1, accuracy: High
        $x_1_4 = "-Fteg" ascii //weight: 1
        $x_1_5 = {81 7d 08 73 77 65 6e}  //weight: 1, accuracy: High
        $x_1_6 = {81 7b 14 4c 74 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_H_2147651603_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.H"
        threat_id = "2147651603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 83 ef 08 ff ce 48 8b 1f 48 83 27 00 48 85 db}  //weight: 5, accuracy: High
        $x_1_2 = {41 81 f8 64 69 73 63}  //weight: 1, accuracy: High
        $x_1_3 = {41 81 f8 72 65 63 76}  //weight: 1, accuracy: High
        $x_1_4 = "-Fteg" ascii //weight: 1
        $x_1_5 = {81 7d 08 73 77 65 6e}  //weight: 1, accuracy: High
        $x_1_6 = {81 7b 14 4c 74 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_K_2147652163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.K"
        threat_id = "2147652163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 43 e5 98 48 c1 ?? 08 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = "cnqazwsxedcrfvtgeabyhnujmikoijlp" ascii //weight: 10
        $x_1_3 = "new/links.php" ascii //weight: 1
        $x_1_4 = "p/task2.php" ascii //weight: 1
        $x_1_5 = "GET /%u?w=%u&i=%u&v=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_K_2147652163_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.K"
        threat_id = "2147652163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 43 e5 98 48 c1 ?? 08 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = "cnqazwsxedcrfvtgeabyhnujmikoijlp" ascii //weight: 10
        $x_1_3 = "new/links.php" ascii //weight: 1
        $x_1_4 = "p/task2.php" ascii //weight: 1
        $x_1_5 = "GET /%u?w=%u&i=%u&v=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_L_2147652733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.L"
        threat_id = "2147652733"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 81 f8 73 65 6e 64 74 ?? 41 81 f8 72 65 63 76 74 45 85 c9}  //weight: 1, accuracy: Low
        $x_1_2 = "\\x64\\release\\shell.pdb" ascii //weight: 1
        $x_1_3 = {81 7f 54 7f 00 00 01 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_L_2147652733_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.L"
        threat_id = "2147652733"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 81 f8 73 65 6e 64 74 ?? 41 81 f8 72 65 63 76 74 45 85 c9}  //weight: 1, accuracy: Low
        $x_1_2 = "\\x64\\release\\shell.pdb" ascii //weight: 1
        $x_1_3 = {81 7f 54 7f 00 00 01 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_M_2147653230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.M"
        threat_id = "2147653230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 81 f8 64 69 73 63}  //weight: 2, accuracy: High
        $x_2_2 = {41 81 f8 63 6e 63 74}  //weight: 2, accuracy: High
        $x_2_3 = {41 81 f8 73 65 6e 64}  //weight: 2, accuracy: High
        $x_2_4 = {41 81 f8 72 65 63 76}  //weight: 2, accuracy: High
        $x_1_5 = "Content-Length: " ascii //weight: 1
        $x_1_6 = "User-Agent: " ascii //weight: 1
        $x_2_7 = {ba 72 65 63 76}  //weight: 2, accuracy: High
        $x_2_8 = {ba 63 6e 63 74}  //weight: 2, accuracy: High
        $x_6_9 = "cnqazwsxedcrfvtgeabyhnujmikoijlp" ascii //weight: 6
        $x_2_10 = {61 73 6b 3f 61 3d [0-4] 26 75 3d 25 75 26 6d 3d 25 78 26 68 3d 25 78}  //weight: 2, accuracy: Low
        $x_2_11 = "IopFailZeroAccessCreate" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_M_2147653230_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.M"
        threat_id = "2147653230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 81 f8 64 69 73 63}  //weight: 2, accuracy: High
        $x_2_2 = {41 81 f8 63 6e 63 74}  //weight: 2, accuracy: High
        $x_2_3 = {41 81 f8 73 65 6e 64}  //weight: 2, accuracy: High
        $x_2_4 = {41 81 f8 72 65 63 76}  //weight: 2, accuracy: High
        $x_2_5 = {ba 72 65 63 76}  //weight: 2, accuracy: High
        $x_2_6 = {ba 63 6e 63 74}  //weight: 2, accuracy: High
        $x_2_7 = {ba 64 69 73 63}  //weight: 2, accuracy: High
        $x_6_8 = "cnqazwsxedcrfvtgeabyhnujmikoijlp" ascii //weight: 6
        $x_2_9 = {61 73 6b 3f 61 3d [0-4] 26 75 3d 25 75 26 6d 3d 25 78 26 68 3d 25 78}  //weight: 2, accuracy: Low
        $x_2_10 = "IopFailZeroAccessCreate" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_N_2147653785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.N"
        threat_id = "2147653785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 47 4e 4f 4c 31 45 00 d1 c0 48 83 c5 04 83 c1 ff 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = "%wZ\\Software\\%08x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_N_2147653785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.N"
        threat_id = "2147653785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 47 4e 4f 4c 31 45 00 d1 c0 48 83 c5 04 83 c1 ff 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = "%wZ\\Software\\%08x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_O_2147654062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.O"
        threat_id = "2147654062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "actioncenter" wide //weight: 1
        $x_1_2 = {f3 0f 7f 00 48 8b 44 24 ?? 48 89 78 04 48 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 16 8b 5f 10 8b 07 48 03 da 48 03 c2 48 8b 08 48 85 c9 0f 84 ?? ?? 00 00 48 bf 00 00 00 00 00 00 00 80 48 85 cf 75 ?? 48 8d 74 0a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_O_2147654062_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.O"
        threat_id = "2147654062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "actioncenter" wide //weight: 1
        $x_1_2 = {f3 0f 7f 00 48 8b 44 24 ?? 48 89 78 04 48 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 16 8b 5f 10 8b 07 48 03 da 48 03 c2 48 8b 08 48 85 c9 0f 84 ?? ?? 00 00 48 bf 00 00 00 00 00 00 00 80 48 85 cf 75 ?? 48 8d 74 0a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_P_2147654466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.P"
        threat_id = "2147654466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 48 8b f8 49 8b ?? f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_P_2147654466_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.P"
        threat_id = "2147654466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 48 8b f8 49 8b ?? f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_Y_2147655285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.Y"
        threat_id = "2147655285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 48 8b f8 49 8b ?? f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = "p2p.64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_Y_2147655285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.Y"
        threat_id = "2147655285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 54 48 8b f8 49 8b ?? f3 a4 0f b7 55 14 44 0f b7 4d 06}  //weight: 1, accuracy: Low
        $x_1_2 = "p2p.64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_V_2147655286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.V"
        threat_id = "2147655286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 d8 8b 43 08 0d 20 20 20 00 3d 60 60 60 00 74 21 3d 63 66 67 00 74 0c 3d 67 6f 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_V_2147655286_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.V"
        threat_id = "2147655286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 d8 8b 43 08 0d 20 20 20 00 3d 60 60 60 00 74 21 3d 63 66 67 00 74 0c 3d 67 6f 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_W_2147655287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.W"
        threat_id = "2147655287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 47 4e 4f 4c 31 06 d1 c0 48 83 c6 04 83 ?? ff 75 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 49 28 48 8d 15 ?? ?? ?? ?? 41 b8 4d 00 00 00 48 83 c1 0c e8}  //weight: 1, accuracy: Low
        $x_1_3 = "81D05F9A-5288-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_W_2147655287_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.W"
        threat_id = "2147655287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 47 4e 4f 4c 31 06 d1 c0 48 83 c6 04 83 ?? ff 75 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 49 28 48 8d 15 ?? ?? ?? ?? 41 b8 4d 00 00 00 48 83 c1 0c e8}  //weight: 1, accuracy: Low
        $x_1_3 = "81D05F9A-5288-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Sirefef_X_2147655288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.X"
        threat_id = "2147655288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1e 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 48 8b 4d 08}  //weight: 1, accuracy: Low
        $x_1_2 = "\\systemroot\\assembly\\GAC_32\\Desktop.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_X_2147655288_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.X"
        threat_id = "2147655288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1e 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 48 8b 4d 08}  //weight: 1, accuracy: Low
        $x_1_2 = "\\systemroot\\assembly\\GAC_32\\Desktop.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AA_2147658112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AA"
        threat_id = "2147658112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 30 63 6e 63 74 48 89 7e 28}  //weight: 1, accuracy: High
        $x_1_2 = {c7 47 30 64 69 73 63 48 89 77 28}  //weight: 1, accuracy: High
        $x_1_3 = "/za.cer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AA_2147658112_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AA"
        threat_id = "2147658112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 30 63 6e 63 74 48 89 7e 28}  //weight: 1, accuracy: High
        $x_1_2 = {c7 47 30 64 69 73 63 48 89 77 28}  //weight: 1, accuracy: High
        $x_1_3 = "/za.cer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AB_2147658655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AB"
        threat_id = "2147658655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 04 24 49 c7 c0 00 80 00 00 48 33 d2 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AB_2147658655_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AB"
        threat_id = "2147658655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 04 24 49 c7 c0 00 80 00 00 48 33 d2 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AG_2147664356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AG"
        threat_id = "2147664356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "v=5.3&id=%08x&aid=%u&sid=%u&q=%" ascii //weight: 1
        $x_1_2 = {c7 47 30 63 6e 63 74 48 89 47 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AG_2147664356_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AG"
        threat_id = "2147664356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "v=5.3&id=%08x&aid=%u&sid=%u&q=%" ascii //weight: 1
        $x_1_2 = {c7 47 30 63 6e 63 74 48 89 47 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AI_2147680079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AI"
        threat_id = "2147680079"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k.replace('about:blank');}}else{k.replace(url);}}" ascii //weight: 1
        $x_1_2 = {33 c0 48 89 07 48 89 47 08 48 89 47 10 48 89 47 18 c7 47 30 63 6e 63 74 48 89 47 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AK_2147682150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AK"
        threat_id = "2147682150"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 38 30 30 30 30 30 30 30 2e 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_10_3 = {89 46 10 b8 47 4e 4f 4c 31 06 d1 c0 [0-4] 83 c2 ff 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sirefef_AL_2147682374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AL"
        threat_id = "2147682374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 09 00 00 00 48 8b cb c7 45 ?? a8 01 00 00 48 c7 45 ?? 00 00 00 60 c7 45 ?? 01 00 00 00 c7 45 ?? 40 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 85 c0 74 01 cc}  //weight: 1, accuracy: Low
        $x_1_2 = "800000cb.@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Sirefef_AN_2147682773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AN"
        threat_id = "2147682773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "80000001.@" ascii //weight: 1
        $x_1_2 = {ba 14 00 00 00 33 c9 ff 15 ?? ?? ?? ?? b9 08 00 00 00 48 8b d8 48 85 c0 74 0f 83 60 08 00 c7 00 01 00 00 00 89 48 04 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AO_2147683234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AO"
        threat_id = "2147683234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 73 06 44 0f b7 5b 14 41 3b f6 74 23 49 8d 7c 1b 2c 8b 17 8b 4f ?? 44 8b 47 ?? 48 03 55 10 49 03 cd e8 ?? ?? ?? ?? 48 83 c7 28 41 03 f7 75 e2 48 8b bd b0 00 00 00 4c 8d 4d 00 41 b8 05 00 00 00 48 2b 7b 30 b2 01 49 8b cd ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AP_2147683235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AP"
        threat_id = "2147683235"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b7 63 06 44 0f b7 5b 14 45 85 e4 74 24 49 8d 7c 1b 2c 8b 17 8b 4f f8 44 8b 47 fc 48 03 55 00 48 03 ce e8 ?? ?? ?? ?? 48 83 c7 28 41 83 c4 ff 75 e1 48 8b 55 ?? 48 8b ce 48 2b 53 30 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sirefef_AQ_2147683626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sirefef.AQ"
        threat_id = "2147683626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "800000cb.@" ascii //weight: 1
        $x_1_2 = {c7 44 24 28 40 00 00 00 66 89 44 24 68 c7 44 24 60 02 00 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

