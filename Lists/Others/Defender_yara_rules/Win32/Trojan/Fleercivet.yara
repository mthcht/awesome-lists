rule Trojan_Win32_Fleercivet_A_2147688790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fleercivet.A"
        threat_id = "2147688790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 58 83 f9 06 74 0e 6a 0a 5a 83 f9 09 0f 45 c2 c9 c3 6a 56 58 c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 30 00 00 ff 75 08 56 57 ff 15 ?? ?? ?? ?? 89 45 ?? 85 c0 74 ?? 56 ff 75 08 ff 75 ?? 50 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 7c 00 5d 00 25 00 30 00 38 00 58 00 5b 00 7c 00 5d 00 25 00 73 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 73 00 5b 00 7c 00 5d 00 25 00 73 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 2e 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 25 00 64 00 5b 00 7c 00 5d 00 10 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "%s\\@system2.att" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Fleercivet_B_2147688918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fleercivet.B"
        threat_id = "2147688918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 1d 8b 04 24 48 8b 4c 24 ?? 0f be 04 01 33 44 24 ?? 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb d2}  //weight: 1, accuracy: Low
        $x_1_2 = {74 61 73 6b 68 6f 73 74 65 78 2e 65 78 65 00 00 5f 4d 41 49 4e 5f 50 52 4f 43 45 53 53 5f 00 00 53 00 6b 00 79 00 70 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fleercivet_D_2147690018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fleercivet.D"
        threat_id = "2147690018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {6a 40 58 83 f9 06 74 0e 6a 0a 5a 83 f9 09 0f 45 c2 c9 c3 6a 56 58 c9 c3}  //weight: 16, accuracy: High
        $x_16_2 = {0f b7 4c 24 34 85 c9 74 17 b8 40 00 00 00 83 f9 06 74 12 83 f9 09 ba 0a 00 00 00 0f 45 c2 eb 05 b8 56 00 00 00}  //weight: 16, accuracy: High
        $x_16_3 = {85 c9 74 19 b8 40 00 00 00 83 f9 06 74 14 83 f9 09 ba 0a 00 00 00 0f 45 c2 8b e5 5d c3 b8 56 00 00 00 8b e5 5d c3}  //weight: 16, accuracy: High
        $x_16_4 = {85 c0 74 17 bb 40 00 00 00 83 f8 06 74 12 b9 0a 00 00 00 83 f8 09 0f 45 d9 eb 05 bb 56 00 00 00 e8 ?? ?? ?? ?? 8b 4d}  //weight: 16, accuracy: Low
        $x_16_5 = {85 c9 74 17 b8 40 00 00 00 83 f9 06 74 12 ba 0a 00 00 00 83 f9 09 0f 45 c2 eb 05 b8 56 00 00 00}  //weight: 16, accuracy: High
        $x_1_6 = {25 00 73 00 5c 00 40 00 73 00 79 00 73 00 74 00 65 00 6d 00 01 00 00 2e 00 61 00 74 00 74 00}  //weight: 1, accuracy: Low
        $x_1_7 = " [%04d-%02d-%02d] [%02d-%02d-%02d-%03d] ->[]<  %s  >" ascii //weight: 1
        $x_1_8 = "[|]%08X[|]%s[|]%d[|]%s[|]127.0.0.1[|]%d[|]%d[|]%d.%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]" wide //weight: 1
        $x_1_9 = {69 70 63 62 33 3d 00 00 74 69 6d 65 75 70 3d 00 64 6e 75 70 31 3d 00 00 64 6e 65 31 3d 00 00 00 63 6c 5f 75 72 6c 31 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_16_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fleercivet_E_2147690591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fleercivet.E"
        threat_id = "2147690591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 58 83 f9 06 74 0e 6a 0a 83 f9 09 5a 0f 45 c2 eb 03 6a 56 58 8b e5 5d c3}  //weight: 2, accuracy: High
        $x_1_2 = {25 00 73 00 5c 00 40 00 73 00 79 00 73 00 74 00 65 00 6d 00 01 00 00 2e 00 61 00 74 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = " [%04d-%02d-%02d] [%02d-%02d-%02d-%03d] ->[]<  %s  >" ascii //weight: 1
        $x_1_4 = "[|]%08X[|]%s[|]%d[|]%s[|]127.0.0.1[|]%d[|]%d[|]%d.%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]%d[|]" wide //weight: 1
        $x_1_5 = {69 70 63 62 33 3d 00 00 74 69 6d 65 75 70 3d 00 64 6e 75 70 31 3d 00 00 64 6e 65 31 3d 00 00 00 63 6c 5f 75 72 6c 31 3d 00 00 00 00 74 69 6d 65 5f 73 69 74 65 31 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fleercivet_F_2147717919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fleercivet.F"
        threat_id = "2147717919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fleercivet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f3 0f 7f 00 a0 ?? ?? ?? ?? 34 0a a2 ?? ?? ?? ?? 84 c0 74 0a 41 80 b9 ?? ?? ?? ?? 00 75 f6}  //weight: 3, accuracy: Low
        $x_1_2 = "cl_url1=" ascii //weight: 1
        $x_1_3 = " [%04d-%02d-%02d] [%02d-%02d-%02d-%03d] ->[]<  %s  >" ascii //weight: 1
        $x_1_4 = {25 00 73 00 5c 00 40 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 2e 00 61 00 74 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 00 73 00 5c 00 40 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 74 00 65 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

