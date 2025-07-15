rule Trojan_Win64_Donut_CIK_2147798636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.CIK!MTB"
        threat_id = "2147798636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 89 c1 83 c0 01 89 45 fc 48 8b 45 10 48 01 c8 0f b7 08 66 89 4d f6 8b 45 f8 c1 e8 08 8b 4d f8 c1 e1 18 09 c8 0f b7 4d f6 01 c1 8b 45 f8 31 c8 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_API_2147798637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.API!MTB"
        threat_id = "2147798637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e4 48 63 c0 48 8b 4d e8 48 01 c1 8b 45 e4 48 63 c0 48 8b 55 10 48 01 c2 8b 45 e4 48 89 4d d8 8b 4d f4 48 89 55 d0 99 f7 f9 48 63 d2 48 8b 45 f8 48 01 d0 48 8b 4d d0 0f be 09 0f be 10 31 d1 48 8b 45 d8 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_AB_2147812527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.AB!MTB"
        threat_id = "2147812527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b8 04 00 00 00 41 8b 04 0b 31 01 48 8d 49 04 49 83 e8 01}  //weight: 1, accuracy: High
        $x_2_2 = {41 03 ca 41 03 c0 41 c1 c2 05 44 33 d1 41 c1 c0 08 44 33 c0 c1 c1 10 41 03 c2 41 03 c8 41 c1 c2 07 41 c1 c0 0d 44 33 d0 44 33 c1 c1 c0 10 48 83 ef 01}  //weight: 2, accuracy: High
        $x_1_3 = {cf ce 7f 31 3a ce 0c 73 7a 82 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Donut_NQ_2147823591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.NQ!MTB"
        threat_id = "2147823591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 48 63 d2 48 8d 05 ?? ?? ?? ?? 48 01 d0 48 8b 4d e0 0f be 09 0f be 10 31 d1 48 8b 45 e8 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_MA_2147849240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.MA!MTB"
        threat_id = "2147849240"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 50 44 48 8b 48 60 46 8b 0c 11 49 83 c2 04 44 0f af 48 40 48 8b 48 68 45 8b c1 41 c1 e8 08 44 88 04 0a ff 40 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_C_2147906065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.C!MTB"
        threat_id = "2147906065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {48 83 ec 20 65 48 8b 04 25 30 00 00 00 49 8b f8 48 8b f2 48 8b e9 45 33 d2 4c 8b 48 60 49 8b 41}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_ND_2147933072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.ND!MTB"
        threat_id = "2147933072"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 8b 06 48 85 c0 74 ?? 48 89 f9 ff d0 49 8b 56 08 48 85 d2 74 ?? 4d 8b 46 10 48 89 f9 e8 3b 0c 00 00 ba 18 00 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {e9 1f 0c 00 00 48 89 c3 49 8b 56 08 48 85 d2 74 ?? 4d 8b 46 10 48 89 f9 e8 07 0c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_MKV_2147942982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.MKV!MTB"
        threat_id = "2147942982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c3 83 e0 0f 0f b6 04 08 30 04 1f 48 ff c3 49 3b de 72 ?? 4c 8d 4c 24 48 41 b8 20 00 00 00 49 8b d6 48 8b cf ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_ZID_2147943831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.ZID!MTB"
        threat_id = "2147943831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 2b c2 41 8b cf 41 2b c9 0f 1f 40 00 42 0f b6 04 02 30 02 48 8d 52 01 48 83 e9 01 75 ef 4d 63 c7 48 8b d7 48 8d 8c 24 ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_GZQ_2147945666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.GZQ!MTB"
        threat_id = "2147945666"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 32 45 20 89 c1 8b 45 fc 48 63 d0 48 8b 45 28 48 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 18 7c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Donut_SLAO_2147946331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donut.SLAO!MTB"
        threat_id = "2147946331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 4a f7 ff 66 c7 42 ff 00 0a 44 89 72 03 66 c7 42 2f 00 0a c6 42 31 0a 44 89 72 47 44 88 72 43 48 8b 05 21 c9 14 00 48 83 c2 58 48 8d 4a f7 48 05 00 0b 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

