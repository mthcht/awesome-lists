rule Ransom_Win32_BlackMatter_ZZ_2147787806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMatter.ZZ"
        threat_id = "2147787806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMatter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {33 c0 8b 55 0c 8b 75 08 ac 80 c6 61 80 ee 61 c1 ca 0d 03 d0 85 c0 75 f0 8b c2}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackMatter_ZY_2147787807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMatter.ZY"
        threat_id = "2147787807"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMatter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {33 c0 8b 55 0c 8b 75 08 66 ad 66 83 f8 41 72 0a 66 83 f8 5a 77 04 66 83 c8 20 80 c6 61 80 ee 61 c1 ca 0d 03 d0 85 c0 75 df}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackMatter_ZX_2147787808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMatter.ZX"
        threat_id = "2147787808"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMatter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {b8 41 42 43 44 ab b8 45 46 47 48 ab b8 49 4a 4b 4c ab b8 4d 4e 4f 50 ab b8 51 52 53 54 ab b8 55 56 57 58 ab b8 59 5a 61 62 ab b8 63 64 65 66 ab b8 67 68 69 6a ab b8 6b 6c 6d 6e ab b8 6f 70 71 72 ab b8 73 74 75 76 ab b8 77 78 79 7a ab b8 30 31 32 33 ab b8 34 35 36 37 ab b8 38 39 2b 2f ab}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackMatter_PA_2147788436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMatter.PA!MTB"
        threat_id = "2147788436"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMatter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ad 66 85 c0 75 ?? 66 b8 ?? ?? 66 ab b8 ?? ?? ?? ?? 35 f8 9f 01 17 ab b8 ?? ?? ?? ?? 35 f8 9f 01 17 ab b8 ?? ?? ?? ?? 35 f8 9f 01 17 ab b8 ?? ?? ?? ?? 35 f8 9f 01 17 ab 66 33 c0 66 ab eb ?? 66 ab eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackMatter_MAK_2147788542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMatter.MAK!MTB"
        threat_id = "2147788542"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMatter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ad 66 83 f8 ?? 72 0a 66 83 f8 5a 80 c6 61 80 ee 61 c1 ca ?? 03 d0 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 37 c1 e6 ?? 03 72 1c 03 f3 ad 03 c3 89 45 fc 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_BlackMatter_PAB_2147795391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackMatter.PAB!MTB"
        threat_id = "2147795391"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMatter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 08 8b 55 0c 81 31 ?? ?? ?? ?? f7 11 83 c1 04 4a 75 f2}  //weight: 2, accuracy: Low
        $x_2_2 = {8b f9 2b cf 0f b6 16 03 c2 46 03 d8 4f 75 f5 bf ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 33 d2 f7 f7 52 8b c3 33 d2 f7 f7 8b da 58 85 c9 75 c5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

