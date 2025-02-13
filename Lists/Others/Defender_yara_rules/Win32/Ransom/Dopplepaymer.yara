rule Ransom_Win32_Dopplepaymer_A_2147745261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.A"
        threat_id = "2147745261"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".readme2unlock.txt" wide //weight: 2
        $x_1_2 = ".locked" wide //weight: 1
        $x_1_3 = "WINDOWS\\SYSTEM32\\*.dll" wide //weight: 1
        $x_1_4 = "File is locked: %ws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_A_2147745261_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.A"
        threat_id = "2147745261"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 b8 17 a1 8b 4c 24 10 89 4c 24 14 8b 4c 24 14 8b 54 24 04 8a 1c 0a 66 8b 74 24 0e 88 5c 24 1b 66 69 7c 24 2e 63 f2 8b 0c 24 03 4c 24 14 66 89 7c 24 2e 89 4c 24 1c 66 39 f0 76 15 c7 44 24 10 00 00 00 00 eb ba 8b 04 24 8d 65 f4 5e 5f 5b 5d c3 8b 44 24 30 8b 4c 24 28 83 f1 ff 35 a9 86 ef 37 89 4c 24 28 8b 4c 24 1c 8a 54 24 1b 88 11 03 44 24 14 89 44 24 10 8b 4c 24 08 39 c8 74 c7 e9 7c ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_A_2147745261_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.A"
        threat_id = "2147745261"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "#herjWRJ@34yherjer" wide //weight: 2
        $x_2_2 = "AssocIsDangerous" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_A_2147745261_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.A"
        threat_id = "2147745261"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b dd 32 c0 8b cb fe c0 d1 e9 8b d1 81 f2 20 83 b8 ed f6 c3 01 8b da 0f 44 d9 3c 08 7c e6 89 1c ae 45 81 fd 00 01 00 00 7c d6}  //weight: 2, accuracy: High
        $x_1_2 = {0f b6 33 4a 33 f0 43 81 e6 ff 00 00 00 c1 e8 08 33 04 b1 83 fa ff 75 e8}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 44 24 08 c1 e0 08 0f b6 4a 11 03 c1 c6 42 10 01 80 3a 00 74 16 8b 7a 08 8b 4a 04 66 89 04 79 ff 42 08 85 c0 75 11 33 c0 40 eb 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Dopplepaymer_A_2147745261_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.A"
        threat_id = "2147745261"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rj57cs9dmafYKN5BqK8OouDC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_A_2147745385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.gen!A"
        threat_id = "2147745385"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~1:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_B_2147745603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.gen!B"
        threat_id = "2147745603"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~1:" wide //weight: 1
        $x_1_2 = "\\system32\\" wide //weight: 1
        $x_1_3 = "\\windows\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_C_2147750943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.gen!C"
        threat_id = "2147750943"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~1:" wide //weight: 1
        $n_1_2 = "***__c8a10b4c-0298-4a21-9dc1-4a843a38e4b4__***" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_D_2147750944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.gen!D"
        threat_id = "2147750944"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~1:" wide //weight: 1
        $x_1_2 = "\\system32\\" wide //weight: 1
        $x_1_3 = "\\windows\\" wide //weight: 1
        $n_1_4 = "***__c8a10b4c-0298-4a21-9dc1-4a843a38e4b4__***" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_Dopplepaymer_KM_2147770407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dopplepaymer.KM!MTB"
        threat_id = "2147770407"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 89 45 ?? eb ?? 8b 45 ?? 8b 4d ?? 8a 14 01 8b 75 ?? 88 14 06 83 c0 01 8b 7d ?? 39 f8 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 01 8b 7d ?? 39 f8 89 45 ?? 74 ?? eb ?? 31 c0 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

