rule Trojan_Win32_Sirefef_A_142985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.A"
        threat_id = "142985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 37 8b ce 23 f0 83 c7 04 c1 e9 08 3b d6 77 0a}  //weight: 1, accuracy: High
        $x_1_2 = {74 f1 5f 5e ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 10 01 00 01 80 ff 74 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_A_142985_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.A"
        threat_id = "142985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 37 8b ce 23 f0 83 c7 04 c1 e9 08 3b d6 77 0a}  //weight: 1, accuracy: High
        $x_1_2 = {74 f1 5f 5e ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 10 01 00 01 80 ff 74 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_B_142986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.B"
        threat_id = "142986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4}  //weight: 1, accuracy: High
        $x_1_2 = {c7 00 10 00 01 00 ff 76 04 6a fe ff 15 ?? ?? ?? ?? 8b 46 04 ?? ?? b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_4 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 ?? ?? ?? ?? 75 19 8b 41 04 c7 80 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {03 c1 25 ff 00 00 00 8a 84 05 ?? ?? ?? ?? 03 fe 30 07 46 3b f2 7c b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_B_142986_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.B"
        threat_id = "142986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4}  //weight: 1, accuracy: High
        $x_1_2 = {c7 00 10 00 01 00 ff 76 04 6a fe ff 15 ?? ?? ?? ?? 8b 46 04 ?? ?? b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_4 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 ?? ?? ?? ?? 75 19 8b 41 04 c7 80 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {03 c1 25 ff 00 00 00 8a 84 05 ?? ?? ?? ?? 03 fe 30 07 46 3b f2 7c b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_A_142991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!A"
        threat_id = "142991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e}  //weight: 10, accuracy: High
        $x_10_2 = "user: 1" ascii //weight: 10
        $x_1_3 = {47 45 54 20 2f 63 6c 69 63 6b 20 48 54 54 50 2f 31 2e 31 [0-5] 75 72 6c 3a 20 25 2e 2a 73 [0-5] 52 65 66 65 72 65 72 3a 20 25 2e 2a 73}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 6f 63 61 74 69 6f 6e 3a 20 68 74 74 70 3a 2f 2f 25 2e 2a 73 [0-5] 73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d [0-5] 77 77 77 2e 67 6f 6f 67 6c 65 [0-5] 73 65 61 72 63 68 2e 6c 69 76 65 2e 63 6f 6d [0-5] 79 61 6e 64 65 78 2e 72 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_A_142991_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!A"
        threat_id = "142991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e}  //weight: 10, accuracy: High
        $x_10_2 = "user: 1" ascii //weight: 10
        $x_1_3 = {47 45 54 20 2f 63 6c 69 63 6b 20 48 54 54 50 2f 31 2e 31 [0-5] 75 72 6c 3a 20 25 2e 2a 73 [0-5] 52 65 66 65 72 65 72 3a 20 25 2e 2a 73}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 6f 63 61 74 69 6f 6e 3a 20 68 74 74 70 3a 2f 2f 25 2e 2a 73 [0-5] 73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d [0-5] 77 77 77 2e 67 6f 6f 67 6c 65 [0-5] 73 65 61 72 63 68 2e 6c 69 76 65 2e 63 6f 6d [0-5] 79 61 6e 64 65 78 2e 72 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_B_142992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!B"
        threat_id = "142992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 65 77 73 2e}  //weight: 10, accuracy: High
        $x_10_2 = "OpenSCManagerW" ascii //weight: 10
        $x_2_3 = {47 45 54 20 2f 69 6e 73 74 61 6c 6c 20 48 54 54 50 2f 31 2e 31 [0-5] 48 6f 73 74 3a 20 25 73 [0-5] 69 64 3a 20 25 64 [0-5] 77 6d 69 64 3a 20 25 64}  //weight: 2, accuracy: Low
        $x_1_4 = ".vertihvostfeed.com /id" ascii //weight: 1
        $x_1_5 = "0D086A5D-67D9-470f-9168-0968FF33BFD9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_B_142992_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!B"
        threat_id = "142992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 65 77 73 2e}  //weight: 10, accuracy: High
        $x_10_2 = "OpenSCManagerW" ascii //weight: 10
        $x_2_3 = {47 45 54 20 2f 69 6e 73 74 61 6c 6c 20 48 54 54 50 2f 31 2e 31 [0-5] 48 6f 73 74 3a 20 25 73 [0-5] 69 64 3a 20 25 64 [0-5] 77 6d 69 64 3a 20 25 64}  //weight: 2, accuracy: Low
        $x_1_4 = ".vertihvostfeed.com /id" ascii //weight: 1
        $x_1_5 = "0D086A5D-67D9-470f-9168-0968FF33BFD9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_C_143037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!C"
        threat_id = "143037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\VC5\\release\\kinject.dll.pdb" ascii //weight: 1
        $x_1_2 = "version=0&err=%s&l=%d&c=%d HTTP/1.1" ascii //weight: 1
        $x_1_3 = {77 77 77 2e 67 6f 6f 67 6c 65 2e [0-6] 25 73 25 73 [0-4] 26 63 78 3d [0-4] 26 63 6c 69 65 6e 74 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "Referer: %S%S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_C_143037_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!C"
        threat_id = "143037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\VC5\\release\\kinject.dll.pdb" ascii //weight: 1
        $x_1_2 = "version=0&err=%s&l=%d&c=%d HTTP/1.1" ascii //weight: 1
        $x_1_3 = {77 77 77 2e 67 6f 6f 67 6c 65 2e [0-6] 25 73 25 73 [0-4] 26 63 78 3d [0-4] 26 63 6c 69 65 6e 74 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "Referer: %S%S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_C_147968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.C"
        threat_id = "147968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4}  //weight: 1, accuracy: High
        $x_1_2 = {eb 0b 81 38 78 56 4f 23 74 09 8b 40 04 3b c3 75 f1 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_C_147968_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.C"
        threat_id = "147968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 8a 04 31 03 d7 30 02 47 3b 7d 0c 7c c4}  //weight: 1, accuracy: High
        $x_1_2 = {eb 0b 81 38 78 56 4f 23 74 09 8b 40 04 3b c3 75 f1 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_G_159678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.G"
        threat_id = "159678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 28 8b 7d 0c 8b 77 60 8b 58 04 8a 06 3c 16 75 18 57 ff 15 ?? ?? ?? ?? fe 47 23 83 47 60 24 57 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 14 89 44 24 20 89 44 24 24 8d 44 24 10 50 c7 44 24 14 18 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 3f 00 3f 00 5c 00 41 00 43 00 50 00 49 00 23 00 50 00 4e 00 50 00 30 00 33 00 30 00 33 00 23 00 32 00 26 00 64 00 61 00 31 00 61 00 33 00 66 00 66 00 26 00 30 00 5c 00 7b 00 31 00 42 00 33 00 37 00 32 00 31 00 33 00 33 00 2d 00 42 00 46 00 46 00 41 00 2d 00 34 00 64 00 62 00 61 00 2d 00 39 00 43 00 43 00 46 00 2d 00 35 00 34 00 37 00 34 00 42 00 45 00 44 00 36 00 41 00 39 00 46 00 36 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 45 00 6e 00 75 00 6d 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 4c 00 45 00 47 00 41 00 43 00 59 00 5f 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 25 00 49 00 36 00 34 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 25 00 73 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Sirefef_G_159678_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.G"
        threat_id = "159678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 28 8b 7d 0c 8b 77 60 8b 58 04 8a 06 3c 16 75 18 57 ff 15 ?? ?? ?? ?? fe 47 23 83 47 60 24 57 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 14 89 44 24 20 89 44 24 24 8d 44 24 10 50 c7 44 24 14 18 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 3f 00 3f 00 5c 00 41 00 43 00 50 00 49 00 23 00 50 00 4e 00 50 00 30 00 33 00 30 00 33 00 23 00 32 00 26 00 64 00 61 00 31 00 61 00 33 00 66 00 66 00 26 00 30 00 5c 00 7b 00 31 00 42 00 33 00 37 00 32 00 31 00 33 00 33 00 2d 00 42 00 46 00 46 00 41 00 2d 00 34 00 64 00 62 00 61 00 2d 00 39 00 43 00 43 00 46 00 2d 00 35 00 34 00 37 00 34 00 42 00 45 00 44 00 36 00 41 00 39 00 46 00 36 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 45 00 6e 00 75 00 6d 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 4c 00 45 00 47 00 41 00 43 00 59 00 5f 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 25 00 49 00 36 00 34 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 25 00 73 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Sirefef_162658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef"
        threat_id = "162658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GET /bad.php?w=%u&i=%s HTTP/1.0" ascii //weight: 1
        $x_1_2 = "stat.php?w=%u&i=%s&a=%u" ascii //weight: 1
        $x_1_3 = {75 70 64 61 74 65 2e 64 62 [0-16] 6e 65 77 2f 31 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 75 00 6e 00 61 00 73 00 00 00 5c 00 3f 00 3f 00 5c 00 25 00 73 00 5c 00 25 00 78 00 25 00 78 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "rundll32.exe \"%s\\%x%x.cpl\",BeginTask *%I64d*%x*%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sirefef_162658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef"
        threat_id = "162658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 20 bf 02 00 ff d6 e8 ?? ?? ?? ?? 85 c0 75 ?? 8d 85 ?? ?? ff ff 50 68 02 02 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_3_2 = "GET /bad.php?w=%u&i=%s HTTP/1.0" ascii //weight: 3
        $x_3_3 = "\\BaseNamedObjects\\{81D05F9A-5343-439f-ACAB-E7822E4416F9}" wide //weight: 3
        $x_1_4 = "User-Agent: Opera/6 (Windows NT %u.%u; U; LangID=%x; %s)" ascii //weight: 1
        $x_1_5 = {78 36 34 00 78 38 36 00}  //weight: 1, accuracy: High
        $x_1_6 = "stat.php?w=%u&i=%s&a=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_162658_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef"
        threat_id = "162658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GET /bad.php?w=%u&i=%s HTTP/1.0" ascii //weight: 1
        $x_1_2 = "stat.php?w=%u&i=%s&a=%u" ascii //weight: 1
        $x_1_3 = {75 70 64 61 74 65 2e 64 62 [0-16] 6e 65 77 2f 31 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 75 00 6e 00 61 00 73 00 00 00 5c 00 3f 00 3f 00 5c 00 25 00 73 00 5c 00 25 00 78 00 25 00 78 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "rundll32.exe \"%s\\%x%x.cpl\",BeginTask *%I64d*%x*%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sirefef_162658_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef"
        threat_id = "162658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 20 bf 02 00 ff d6 e8 ?? ?? ?? ?? 85 c0 75 ?? 8d 85 ?? ?? ff ff 50 68 02 02 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_3_2 = "GET /bad.php?w=%u&i=%s HTTP/1.0" ascii //weight: 3
        $x_3_3 = "\\BaseNamedObjects\\{81D05F9A-5343-439f-ACAB-E7822E4416F9}" wide //weight: 3
        $x_1_4 = "User-Agent: Opera/6 (Windows NT %u.%u; U; LangID=%x; %s)" ascii //weight: 1
        $x_1_5 = {78 36 34 00 78 38 36 00}  //weight: 1, accuracy: High
        $x_1_6 = "stat.php?w=%u&i=%s&a=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_H_165676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.H"
        threat_id = "165676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\ACPI#PNP0303#2&da1a3ff&0\\U\\$%08x" wide //weight: 1
        $x_1_2 = "ZwQueueApcThread" ascii //weight: 1
        $x_1_3 = "ZwTestAlert" ascii //weight: 1
        $x_1_4 = {50 50 68 00 00 40 00 6a 05 50 50 50 54 68 80 02 40 00 68 00 00 10 00 54 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_H_165676_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.H"
        threat_id = "165676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\ACPI#PNP0303#2&da1a3ff&0\\U\\$%08x" wide //weight: 1
        $x_1_2 = "ZwQueueApcThread" ascii //weight: 1
        $x_1_3 = "ZwTestAlert" ascii //weight: 1
        $x_1_4 = {50 50 68 00 00 40 00 6a 05 50 50 50 54 68 80 02 40 00 68 00 00 10 00 54 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_I_166222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.I"
        threat_id = "166222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 10 8b 70 48 8b (1d|3d) ?? ?? ?? ?? 33 (db|ff)}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 0c 83 c4 0c 8d 85 ?? ?? ?? ?? 50 ff 75 ?? c7 85 00 01 00 01 00 89 75 0c ff 15 ?? ?? ?? ?? 85 c0 7c ?? 6a 40 68 00 10 00 00 8d 45 0c 50}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 0c 6a 40 68 00 10 00 00 8d 45 fc 50 57 8d 85 ?? ?? ff ff 50 ff 75 08 c7 85 ?? ?? ff ff 02 00 01 00 89 75 fc ff 15 ?? ?? ?? ?? 85 c0 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_I_166222_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.I"
        threat_id = "166222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 10 8b 70 48 8b (1d|3d) ?? ?? ?? ?? 33 (db|ff)}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 0c 83 c4 0c 8d 85 ?? ?? ?? ?? 50 ff 75 ?? c7 85 00 01 00 01 00 89 75 0c ff 15 ?? ?? ?? ?? 85 c0 7c ?? 6a 40 68 00 10 00 00 8d 45 0c 50}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 0c 6a 40 68 00 10 00 00 8d 45 fc 50 57 8d 85 ?? ?? ff ff 50 ff 75 08 c7 85 ?? ?? ff ff 02 00 01 00 89 75 fc ff 15 ?? ?? ?? ?? 85 c0 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_J_166574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.J"
        threat_id = "166574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%wZ\\Software\\%08x" wide //weight: 1
        $x_1_2 = "hcnct" ascii //weight: 1
        $x_1_3 = {81 7d 0c 73 65 6e 64 74 ?? 81 7d 0c 72 65 63 76 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_J_166574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.J"
        threat_id = "166574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%wZ\\Software\\%08x" wide //weight: 1
        $x_1_2 = "hcnct" ascii //weight: 1
        $x_1_3 = {81 7d 0c 73 65 6e 64 74 ?? 81 7d 0c 72 65 63 76 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_P_167506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.P"
        threat_id = "167506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 64 69 73 63 0f 84 ?? ?? ?? ?? 3d 73 65 6e 64}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08 8b 75 08 8b 7d 90 01 01 03 f1 03 f9 8b 48 90 01 01 83 c0 28 4a f3 a4 75 e9}  //weight: 10, accuracy: High
        $x_10_3 = {53 68 73 65 6e 64 8b c7 8b ce e8 ?? ?? ?? ?? 8b d8 85 db 75 0d ff 76 ?? e8 ?? ?? ?? ?? 6a 08 58}  //weight: 10, accuracy: Low
        $x_1_4 = {c6 06 e8 6a 07 56 c6 46 05 eb c6 46 06 ?? ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_P_167506_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.P"
        threat_id = "167506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 64 69 73 63 0f 84 ?? ?? ?? ?? 3d 73 65 6e 64}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08 8b 75 08 8b 7d fc 03 f1 03 f9 8b 48 fc 83 c0 28 4a f3 a4 75 e9}  //weight: 10, accuracy: High
        $x_10_3 = {53 68 73 65 6e 64 8b c7 8b ce e8 ?? ?? ?? ?? 8b d8 85 db 75 0d ff 76 ?? e8 ?? ?? ?? ?? 6a 08 58}  //weight: 10, accuracy: Low
        $x_1_4 = {c6 06 e8 6a 07 56 c6 46 05 eb c6 46 06 ?? ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_Q_167528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.Q"
        threat_id = "167528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 4f 01 0f af c1 33 d2 6a 19 59 f7 f1 83 c2 61 66 89 16 83 c6 02 85 ff 75 ?? 33 c0 66 89 06 07 00 4f ff 15}  //weight: 5, accuracy: Low
        $x_2_2 = {81 ec f8 07 00 00 8b 45 ?? 83 65 ?? 00 53 56 57 c7 85 0c f8 ff ff 07 00 01 00 85 c0 0f 84}  //weight: 2, accuracy: Low
        $x_2_3 = {89 74 24 30 c7 84 24 ?? ?? 00 00 07 00 01 00 39 5d 08 75 07 33 c0 e9 ?? ?? ?? ?? 8b 4d 08 8d 51 01 8a 01 41 84 c0 75 f9}  //weight: 2, accuracy: Low
        $x_2_4 = {ff 75 f8 ff 75 f4 50 ff 52 40 85 c0 0f 85 ?? ?? 00 00 8b 45 fc 8b 08 50 ff 51 54}  //weight: 2, accuracy: Low
        $x_1_5 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d}  //weight: 1, accuracy: High
        $x_1_6 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 1
        $x_1_7 = "_update.exe" wide //weight: 1
        $x_1_8 = "\\syswow64\\dfrgui.exe" wide //weight: 1
        $x_1_9 = "*\\shellex\\ContextMenuHandlers\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_Q_167528_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.Q"
        threat_id = "167528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 4f 01 0f af c1 33 d2 6a 19 59 f7 f1 83 c2 61 66 89 16 83 c6 02 85 ff 75 ?? 33 c0 66 89 06 07 00 4f ff 15}  //weight: 5, accuracy: Low
        $x_2_2 = {81 ec f8 07 00 00 8b 45 ?? 83 65 ?? 00 53 56 57 c7 85 0c f8 ff ff 07 00 01 00 85 c0 0f 84}  //weight: 2, accuracy: Low
        $x_2_3 = {89 74 24 30 c7 84 24 ?? ?? 00 00 07 00 01 00 39 5d 08 75 07 33 c0 e9 ?? ?? ?? ?? 8b 4d 08 8d 51 01 8a 01 41 84 c0 75 f9}  //weight: 2, accuracy: Low
        $x_2_4 = {ff 75 f8 ff 75 f4 50 ff 52 40 85 c0 0f 85 ?? ?? 00 00 8b 45 fc 8b 08 50 ff 51 54}  //weight: 2, accuracy: Low
        $x_1_5 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d}  //weight: 1, accuracy: High
        $x_1_6 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 1
        $x_1_7 = "_update.exe" wide //weight: 1
        $x_1_8 = "\\syswow64\\dfrgui.exe" wide //weight: 1
        $x_1_9 = "*\\shellex\\ContextMenuHandlers\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_S_167778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.S"
        threat_id = "167778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /p/task2.php?w=%u&i=%S&n=%u" ascii //weight: 1
        $x_1_2 = "%wZ\\Software\\%08x" wide //weight: 1
        $x_1_3 = {3d 05 00 00 80 74 cf 33 ff 3b c7 0f 8c a7 00 00 00 33 db 43 39 5e 04 0f 85 9b 00 00 00 8b 46 08 83 f8 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_S_167778_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.S"
        threat_id = "167778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /p/task2.php?w=%u&i=%S&n=%u" ascii //weight: 1
        $x_1_2 = "%wZ\\Software\\%08x" wide //weight: 1
        $x_1_3 = {3d 05 00 00 80 74 cf 33 ff 3b c7 0f 8c a7 00 00 00 33 db 43 39 5e 04 0f 85 9b 00 00 00 8b 46 08 83 f8 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_V_167993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.V"
        threat_id = "167993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 3d ff 00 00 00 75 7a 8b ?? ?? 0f b6 51 01 83 fa 15 75 65 8b ?? ?? 8b 48 02}  //weight: 10, accuracy: Low
        $x_1_2 = "|POST /ajax/chat/send.php?" ascii //weight: 1
        $x_1_3 = {63 00 6f 00 6f 00 6c 00 63 00 6f 00 72 00 65 00 ?? ?? ?? ?? 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SkinuxWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_V_167993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.V"
        threat_id = "167993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 3d ff 00 00 00 75 7a 8b ?? ?? 0f b6 51 01 83 fa 15 75 65 8b ?? ?? 8b 48 02}  //weight: 10, accuracy: Low
        $x_1_2 = "|POST /ajax/chat/send.php?" ascii //weight: 1
        $x_1_3 = {63 00 6f 00 6f 00 6c 00 63 00 6f 00 72 00 65 00 ?? ?? ?? ?? 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SkinuxWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_AB_170819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AB"
        threat_id = "170819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06}  //weight: 1, accuracy: High
        $x_1_2 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AB_170819_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AB"
        threat_id = "170819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06}  //weight: 1, accuracy: High
        $x_1_2 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AD_171077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AD"
        threat_id = "171077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 61 00 63 00 74 00 69 00 6f 00 6e 00 63 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 14 8b 46 0c 85 c0 75 ?? e9 ?? 00 00 00 8b 5e 10 8b 06 03 5d 08 03 45 08 eb 1d 78 15 8b 55 08 8d 74 11 02 6a 12 bf ?? ?? ?? ?? 59 33 d2 f3 a6 74 11 83 c3 04 83 c0 04 8b 08 85 c9 75 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AD_171077_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AD"
        threat_id = "171077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 61 00 63 00 74 00 69 00 6f 00 6e 00 63 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 14 8b 46 0c 85 c0 75 ?? e9 ?? 00 00 00 8b 5e 10 8b 06 03 5d 08 03 45 08 eb 1d 78 15 8b 55 08 8d 74 11 02 6a 12 bf ?? ?? ?? ?? 59 33 d2 f3 a6 74 11 83 c3 04 83 c0 04 8b 08 85 c9 75 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AF_171537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AF"
        threat_id = "171537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 3f 00 3f 00 5c 00 41 00 43 00 50 00 49 00 23 00 50 00 4e 00 50 00 30 00 33 00 30 00 33 00 23 00 32 00 26 00 64 00 61 00 31 00 61 00 33 00 66 00 66 00 26 00 30 00 5c 00 55 00 5c 00 ?? 00 25 00 30 00 38 00 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 71 0e 0f b7 41 0c 83 65 f8 00 8d 44 c1 10 85 f6 74 49 8b ce c1 e1 03 2b ca 03 c8 3b 4d fc 73 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AF_171537_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AF"
        threat_id = "171537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 3f 00 3f 00 5c 00 41 00 43 00 50 00 49 00 23 00 50 00 4e 00 50 00 30 00 33 00 30 00 33 00 23 00 32 00 26 00 64 00 61 00 31 00 61 00 33 00 66 00 66 00 26 00 30 00 5c 00 55 00 5c 00 ?? 00 25 00 30 00 38 00 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 71 0e 0f b7 41 0c 83 65 f8 00 8d 44 c1 10 85 f6 74 49 8b ce c1 e1 03 2b ca 03 c8 3b 4d fc 73 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AG_171641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AG"
        threat_id = "171641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 47 4e 4f 4c 31 06 d1 c0 83 c6 04 49 75 f6}  //weight: 2, accuracy: High
        $x_1_2 = {8b 46 18 6a 4d 83 c0 0c 68 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 10 6a 46 83 c0 0c 68 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_2_4 = {8b 4b 54 57 8b fd f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08}  //weight: 2, accuracy: High
        $x_2_5 = {c7 43 08 30 30 31 00 c6 43 05 03 c7 43 54 30 30 32 00 c6 43 51 03 ff 15}  //weight: 2, accuracy: High
        $x_2_6 = "%wZ\\Software\\%08x" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_AG_171641_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AG"
        threat_id = "171641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 47 4e 4f 4c 31 06 d1 c0 83 c6 04 49 75 f6}  //weight: 2, accuracy: High
        $x_1_2 = {8b 46 18 6a 4d 83 c0 0c 68 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 10 6a 46 83 c0 0c 68 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_2_4 = {8b 4b 54 57 8b fd f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08}  //weight: 2, accuracy: High
        $x_2_5 = {c7 43 08 30 30 31 00 c6 43 05 03 c7 43 54 30 30 32 00 c6 43 51 03 ff 15}  //weight: 2, accuracy: High
        $x_2_6 = "%wZ\\Software\\%08x" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sirefef_AK_173488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AK"
        threat_id = "173488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 73 65 6e 64 74 90 01 01 3d 72 65 63 76 74}  //weight: 1, accuracy: High
        $x_1_2 = "\\%08x.@" ascii //weight: 1
        $x_1_3 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 10 00 00 24 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {d1 37 0c 1e 3f a3 64 1e 2b d7 a6 ea c7 e7 18 c1 10 00 00 a4 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sirefef_AK_173488_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AK"
        threat_id = "173488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 73 65 6e 64 74 90 01 01 3d 72 65 63 76 74}  //weight: 1, accuracy: High
        $x_1_2 = "\\%08x.@" ascii //weight: 1
        $x_1_3 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 10 00 00 24 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {d1 37 0c 1e 3f a3 64 1e 2b d7 a6 ea c7 e7 18 c1 10 00 00 a4 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sirefef_AL_173532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AL"
        threat_id = "173532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 78 56 34 12 31 08 d1 c1 83 c0 04 4b 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {74 1e 68 02 01 00 00 eb 0e ff 75 f4 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AL_173532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AL"
        threat_id = "173532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 78 56 34 12 31 08 d1 c1 83 c0 04 4b 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {74 1e 68 02 01 00 00 eb 0e ff 75 f4 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AN_174344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AN"
        threat_id = "174344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 64 69 73 63 74 ?? 3d 73 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 06 89 46 04 89 46 08 89 46 0c 89 46 10 89 46 18 c7 46 1c 63 6e 63 74}  //weight: 1, accuracy: High
        $x_1_3 = "&aid=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_AN_174344_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AN"
        threat_id = "174344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 64 69 73 63 74 ?? 3d 73 65 6e 64}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 06 89 46 04 89 46 08 89 46 0c 89 46 10 89 46 18 c7 46 1c 63 6e 63 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AQ_174871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AQ"
        threat_id = "174871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 7e 0e 2e 75 07 66 83 7e 0c 2e 74 ?? 66 8b 46 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 0c 75 2d 8b 50 06 33 d1 89 15 ?? ?? ?? ?? 8b d6 66 33 50 0a 66 89 15 ?? ?? ?? ?? 8b 10 33 d1 89 15 ?? ?? ?? ?? 66 33 70 04 66 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_AQ_174871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.AQ"
        threat_id = "174871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 7e 0e 2e 75 07 66 83 7e 0c 2e 74 ?? 66 8b 46 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 0c 75 2d 8b 50 06 33 d1 89 15 ?? ?? ?? ?? 8b d6 66 33 50 0a 66 89 15 ?? ?? ?? ?? 8b 10 33 d1 89 15 ?? ?? ?? ?? 66 33 70 04 66 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_BE_182401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.BE"
        threat_id = "182401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00 37 00 35 00 2d 00 38 00 38 00 35 00 37 00 2d 00 34 00 38 00 35 00 30 00 2d 00 39 00 32 00 37 00 37 00 2d 00 31 00 31 00 62 00 38 00 35 00 62 00 64 00 62 00 38 00 65 00 30 00 39 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff 70 54 ff 75 08 ff 75 0c ff 55 18 8b 45 ?? 8b 4d 0c 2b 48 34 89 4d ?? 83 65 ?? 00 eb 07}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 31 c0 00 00 66 89 03 b8 6a 01 00 00 66 89 43 02 c6 43 04 68 83 4b 05 ff 66 c7 43 09 50 50 66 c7 43 0b 50 50 c6 43 0d e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_BE_182401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.BE"
        threat_id = "182401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00 37 00 35 00 2d 00 38 00 38 00 35 00 37 00 2d 00 34 00 38 00 35 00 30 00 2d 00 39 00 32 00 37 00 37 00 2d 00 31 00 31 00 62 00 38 00 35 00 62 00 64 00 62 00 38 00 65 00 30 00 39 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff 70 54 ff 75 08 ff 75 0c ff 55 18 8b 45 ?? 8b 4d 0c 2b 48 34 89 4d ?? 83 65 ?? 00 eb 07}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 31 c0 00 00 66 89 03 b8 6a 01 00 00 66 89 43 02 c6 43 04 68 83 4b 05 ff 66 c7 43 09 50 50 66 c7 43 0b 50 50 c6 43 0d e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sirefef_BT_198725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.BT"
        threat_id = "198725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 09 47 56 c7 45 ?? a8 01 00 00 c7 45 ?? 00 00 00 60 89 7d ?? c7 45 ?? 40 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 85 c0 74 0a 9c 81 0c 24 00 01 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_2 = "800000cb.@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Sirefef_BW_199124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.BW"
        threat_id = "199124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "80000001.@" ascii //weight: 1
        $x_1_2 = {8d 46 0c 50 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 0e 83 60 08 00 c7 00 01 00 00 00 89 70 04 c3 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sirefef_CD_199498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.CD"
        threat_id = "199498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "800000cb.@" ascii //weight: 1
        $x_1_2 = {81 fb 41 50 33 32 75 0b 8b 5e 04 83 fb 18 72 03 8b 46 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Sirefef_202074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sirefef.gen!inj"
        threat_id = "202074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "inj: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 64 8b 35 30 00 00 00 8b 76 0c 8b 76 1c 8b 46 08 8b 7e 20 8b 36 80 3f 6b 75 f3 80 7f 18 00 75 ed 5f 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

