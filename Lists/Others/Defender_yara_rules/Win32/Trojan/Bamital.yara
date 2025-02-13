rule Trojan_Win32_Bamital_A_2147627987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.A"
        threat_id = "2147627987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 02 eb 04 8b cb f3 a4 c6 07 e9 03 00 80 3e (e9|00)}  //weight: 2, accuracy: Low
        $x_1_2 = {74 06 c7 00 6e 6f 6e 65}  //weight: 1, accuracy: High
        $x_1_3 = {74 06 83 c0 07 c6 00 30}  //weight: 1, accuracy: High
        $x_1_4 = {6b 23 00 23 65 6e 64 23 00 3c 74}  //weight: 1, accuracy: High
        $x_1_5 = {8b c8 8b 7d 08 d2 0f 83 c7 ?? e2 f9}  //weight: 1, accuracy: Low
        $x_1_6 = {2a f2 8a 07 3c 00 72 0c 38 f0 77 08 04 ff 2a c2 04 01 eb 02 2a c2 88 07}  //weight: 1, accuracy: High
        $x_2_7 = {74 22 b9 05 00 00 00 8d 35 ?? ?? ?? ?? 8d 3d ?? ?? ?? ?? 83 c7 22 f3 a4 c6 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Bamital_C_2147629854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.C"
        threat_id = "2147629854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 66 6c 61 67 73 2e 69 6e 69 00 31 39 30 39 31 39 37 39}  //weight: 2, accuracy: High
        $x_2_2 = {5b 25 6b 65 79 5d 00 5b 25 61 64 5f 75 72 6c 73 5d 00 5b 25 73 65 5f 75 72 6c 73 5d}  //weight: 2, accuracy: High
        $x_1_3 = {67 6f 6f 67 6c 65 2e 00 73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d 00 62 69 6e 67 2e 63 6f 6d 00 2f 75 72 6c 3f 00 47 45 54}  //weight: 1, accuracy: High
        $x_1_4 = ".overture.com" ascii //weight: 1
        $x_1_5 = "/url?sa=t&source" ascii //weight: 1
        $x_1_6 = "&url=http%3A%2F%2F" ascii //weight: 1
        $x_1_7 = "<div class=\"sb_adsW\">" ascii //weight: 1
        $x_1_8 = "X55 Fut 2999" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Bamital_D_2147630250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.D"
        threat_id = "2147630250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 63 75 72 73 74 06}  //weight: 1, accuracy: High
        $x_1_2 = {74 16 5e 59 c0 06 ?? 83 c6 01 e2 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_E_2147631416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.E"
        threat_id = "2147631416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 fc 8b 45 08 ff d6 61 eb 06 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 fc b9 01 00 00 00 8b 45 08 ff d6 61 eb 0b 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 75 f0 b9 01 00 00 00 8b 45 08 ff d6 61 eb 0b 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 75 ec b9 01 00 00 00 8b 45 08 ff d6 61 eb 0b 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {58 8b 75 e4 b9 01 00 00 00 8b 45 08 ff d6 61 eb 0b 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 75 e4 b9 01 00 00 00 8b 45 08 ff d6 61 eb 0b 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 7d fc b9 01 00 00 00 8b 45 08 ff d7 61 eb 0b 83 7d 0c 00 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bamital_H_2147636446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.H"
        threat_id = "2147636446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 05 0e 30 00 10 72 65 89 45 fc 68 1c 30 00 10 68 2a 30 00 10 e8 87 ff ff ff 8b d0 8d 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_G_2147637454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.G"
        threat_id = "2147637454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 01 75 17 60 68 ?? ?? ?? ?? e8 (75|7d) ff ff ff 0b c0 74 07 8b c8 8b 45 08 ff d1 61}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d 0c 01 75 1b 60 8d 15 ?? ?? ?? ?? 52 e8 05 01 01 01 01 01 3c 4b 61 62 6e ff ff ff 8b c8 0b c9 74 07 8b d0 8b 45 08 ff d2 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bamital_I_2147640978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.I"
        threat_id = "2147640978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_tlst\"><" ascii //weight: 1
        $x_1_2 = {00 67 7a 69 70 00 73 64 63 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5b 25 6b 65 79 5d 00 5b 25 73 75 62 69 64 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_J_2147642810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.J"
        threat_id = "2147642810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 01 75 1d 60 8d 15 ?? ?? ?? ?? 52 e8 05 01 01 01 01 01 03 0e 61 69 6b ff ff ff 8b c8 0b c9 74 09 8b d0 b8 03 00 00 00 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_M_2147644720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.M"
        threat_id = "2147644720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 01 75 1b 60 68 ?? ?? ?? ?? e8 58 ff ff ff 8b c8 0b c9 74 09 8b d0 b8 03 00 00 00 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_N_2147646084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.N"
        threat_id = "2147646084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[%subid]" ascii //weight: 1
        $x_1_2 = "DisableSR" ascii //weight: 1
        $x_1_3 = {8b 45 0c 8b 4d 08 80 38 e9 75 09 39 48 01 75 04 c9 c2 14 00 8b 55 0c 2b 55 14 52 ff 75 18 e8 ?? ?? ?? ?? 8b 4d 0c 66 8b 50 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_O_2147649951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.O"
        threat_id = "2147649951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 ff d0 c9 c2 04 00 b8 00 00 00 00 c9 c2 04 00 55 8b ec 83 7d 0c 01 75 (09|10)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bamital_H_2147678301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bamital.gen!H"
        threat_id = "2147678301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 8b f8 8b f0 03 75 0c 03 7d 10 53 57 56 ff 75 08 e8 19 ff ff ff 5f 59 83 c7 28 e2 a3 c9}  //weight: 1, accuracy: High
        $x_1_2 = {89 01 c7 41 04 2e 64 61 74 c7 41 08 00 00 00 00 8d 45 ?? 50 ff 75 08 e8 ?? ?? ?? ?? 89 45 e0}  //weight: 1, accuracy: Low
        $x_1_3 = {83 3c 03 00 75 16 c7 04 03 01 00 00 00 8d 0d ?? ?? ?? ?? 83 c1 04 03 cb 8b c1 ff d1 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

