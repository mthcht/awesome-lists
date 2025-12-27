rule Trojan_Win64_Shelma_AT_2147837891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelma.AT!MTB"
        threat_id = "2147837891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff c2 48 63 c2 48 8d 4c 24 20 48 03 c8 0f b6 01 41 88 04 38 44 88 09 41 0f b6 0c 38 49 03 c9 0f b6 c1 0f b6 4c 04 20 41 30 0e 49 ff c6 49 83 ea 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelma_AS_2147837903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelma.AS!MTB"
        threat_id = "2147837903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 01 c8 4d 63 c8 44 0f be 42 ff 45 8d 04 58 4d 63 c0 4f 8d 04 98 49 c1 e0 04 4d 01 c8 47 8b 04 82 45 89 c1 41 c1 f9 03 41 83 e1 01 44 88 0c 81}  //weight: 1, accuracy: High
        $x_1_2 = {41 39 c0 7e 0d 44 8a 0c 02 44 30 0c 01 48 ff c0 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelma_SXO_2147888494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelma.SXO!MTB"
        threat_id = "2147888494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 b2 b8 63 00 00 00 88 45 b3 b8 6f 00 00 00 88 45 b4 b8 64 00 00 00 88 45 b5 b8 65 00 00 00 88 45 b6 b8 66 00 00 00 88 45 b7 b8 6f 00 00 00 88 45 b8 b8 78 00 00 00 88 45 b9 b8 2e 00 00 00 88 45 ba b8 74 00 00 00 88 45 bb b8 61 00 00 00 88 45 bc b8 6f 00 00 00 88 45 bd b8 62 00 00 00 88 45 be b8 61 00 00 00 88 45 bf b8 6f 00 00 00 88 45 c0 b8 2e 00 00 00 88 45 c1 b8 63 00 00 00 88 45 c2 b8 6f 00 00 00 88 45 c3 b8 6d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelma_SPX_2147900232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelma.SPX!MTB"
        threat_id = "2147900232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b7 04 48 48 ff c1 48 33 c2 48 6b c0 1f 48 03 d0 49 3b c9 7c e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelma_DAS_2147901049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelma.DAS!MTB"
        threat_id = "2147901049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 39 d0 74 13 48 89 c1 83 e1 1f 8a 4c 0c ?? 41 30 0c 00 48 ff c0 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelma_PGSH_2147958887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelma.PGSH!MTB"
        threat_id = "2147958887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f3 41 0f 6f 04 07 48 8d 49 ?? 83 c2 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 0c 07 f3 0f 6f 41 ?? 66 0f 6f ca 0f 57 c2 f3 41 0f 7f 44 07 ?? f3 41 0f 6f 44 07 ?? 0f 57 c8 f3 41 0f 7f 4c 07 ?? f3 41 0f 6f 44 07 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 4c 07 ?? 48 83 c0 ?? 48 3d ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
        $x_5_2 = {f3 0f 6f 40 ?? 48 8d 40 ?? 66 0f 6f ca 0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c2 f3 0f 7f 40 ?? f3 0f 6f 40 ?? 0f 57 c8 f3 0f 7f 48 ?? 66 0f 6f ca f3 0f 6f 40 ?? 0f 57 c8 f3 0f 7f 48 ?? 48 83 ea 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

