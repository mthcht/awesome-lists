rule Trojan_MSIL_Noon_NBL_2147895313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.NBL!MTB"
        threat_id = "2147895313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0e 11 16 8f 05 00 00 01 25 47 7e 03 00 00 04 19 11 16 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 16 58 13 16 11 16 11 0e 8e 69 33 d4}  //weight: 1, accuracy: High
        $x_1_2 = {11 34 11 0d 1d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 08 32 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_NBL_2147895313_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.NBL!MTB"
        threat_id = "2147895313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 7e 27 00 00 04 60 80 27 00 00 04 38 80 00 00 00 11 07 2d 56 11 05 11 06 28 58 00 00 06 2c 28 06 20 02 7e c3 04 07 61 09 58 66 66 65 65 66 65 66 66 65 65 66 08 59 61 0a 1f 10 7e 27 00 00 04 60 80 27 00 00 04 2b 49}  //weight: 1, accuracy: High
        $x_1_2 = {17 11 0b 5f 2d 20 11 21 20 ff ed 49 bf 06 61 07 61 5a 20 c1 30 ed 66 06 59 07 58 58 13 21 11 21 1f 10 64 d1 13 1b 11 1b d2 13 2d 11 1b 1e 63 d1 13 1b 11 1a 11 0b 91 13 29 11 1a 11 0b 11 29 11 25 61 19 11 1f 58 61 11 2d 61 d2 9c 11 29 13 1f 17 11 0b 58 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_KAC_2147896276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.KAC!MTB"
        threat_id = "2147896276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18 08 11 17 6f ?? 00 00 0a 13 19 07 11 15 17 58 09 5d 91 13 1a 11 18 11 19 11 1a 28 ?? 00 00 06 13 1b 07 11 16 11 1b 20 ?? ?? 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_KAD_2147896280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.KAD!MTB"
        threat_id = "2147896280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? 00 00 0a 13 0d 02 07 11 09 28 ?? 00 00 06 13 0e 02 11 0c 11 0d 11 0e 28 ?? 00 00 06 13 0f 07 11 0a 11 0f 20 ?? ?? 00 00 5d d2 9c 11 09 17 59 13 09 11 09 16 2f b2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_MBYP_2147912642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.MBYP!MTB"
        threat_id = "2147912642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 11 12 61 13 13 11 04 17 58 11 05 8e 69 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_PLIPH_2147932024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.PLIPH!MTB"
        threat_id = "2147932024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {0f 00 18 1f 5f 28 ?? 00 00 06 1f 10 62 0f 00 20 9d 02 00 00 20 c3 02 00 00 28 ?? 00 00 06 1e 62 60 0f 00 28 ?? 00 00 0a 60 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_HHM_2147935596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.HHM!MTB"
        threat_id = "2147935596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00}  //weight: 6, accuracy: Low
        $x_5_2 = {0a 61 d2 0d 1a 00 00 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 61 0f 00 28 ?? 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZHH_2147936579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZHH!MTB"
        threat_id = "2147936579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 11 0c}  //weight: 6, accuracy: Low
        $x_5_2 = {9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_EAAN_2147937524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.EAAN!MTB"
        threat_id = "2147937524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 11 07 11 07 19 5d 2c 09 11 07 1b 5d 16 fe 01 2b 01 17 9c 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08 2d d7}  //weight: 5, accuracy: High
        $x_5_2 = {11 0d 11 0e 6f 1c 00 00 0a 13 0f 00 09 11 0f 1f 11 5a 58 0d 09 09 19 62 09 1b 63 60 61 0d 00 11 0e 17 58 13 0e 11 0e 11 0d 6f 1d 00 00 0a 32 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZZE_2147937806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZZE!MTB"
        threat_id = "2147937806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {03 09 11 05 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 20 ?? 00 00 00 fe 04 13 06 11 06 2c 04 07 17 d6 0b 11 05 17 d6 13 05 11 05 11 04 31 d1}  //weight: 6, accuracy: Low
        $x_5_2 = {b7 0f 01 28 ?? 00 00 0a 6c 23 bc 74 93 18 04 56 d6 3f 5a 0f 01 28 ?? 00 00 0a 6c 23 c1 ca a1 45 b6 f3 e5 3f 5a 58 0f 01 28 ?? 00 00 0a 6c 23 1b 2f dd 24 06 81 c5 3f 5a 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_EANJ_2147941296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.EANJ!MTB"
        threat_id = "2147941296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {17 13 0e 11 0d 6c 28 9c 00 00 0a 28 8d 00 00 0a b7 13 0f 18 13 10 2b 1a 11 0d 11 10 5d 16 fe 01 13 11 11 11 2c 05 16 13 0e 2b 0d 00 11 10 17 d6 13 10 11 10 11 0f 31 e0 11 0e 13 12 11 12 2c 07 11 06 17 d6 13 06 00 00 11 0d 17 d6 13 0d 11 0d 20 88 13 00 00 31 a9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZBU_2147941880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZBU!MTB"
        threat_id = "2147941880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 12 01 28 ?? 00 00 0a 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 32 29 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 47 11 06 16 31 42 19 8d ?? 00 00 01 25 16 12 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZDT_2147942935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZDT!MTB"
        threat_id = "2147942935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 1e 11 1f 6f ?? 00 00 0a 13 22 12 22 28 ?? 00 00 0a 16 61 d2 13 23 12 22 28 ?? 00 00 0a 16 61 d2 13 24 12 22 28 ?? 00 00 0a 16 61 d2 13 25 19 8d ?? 00 00 01 13 26 11 26 16 11 23 6c 23 00 00 00 00 00 e0 6f 40 5b a1 11 26 17 11 24 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZIT_2147943239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZIT!MTB"
        threat_id = "2147943239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 17 11 21 6f ?? 00 00 0a 13 23 73 50 00 00 0a 13 24 11 24 72 ?? ?? 00 70 11 17 11 21 73 5f 00 00 0a 6f ?? 00 00 0a 00 11 24 72 ?? ?? 00 70 28 ?? 00 00 0a 8c 2a 00 00 01 6f ?? 00 00 0a 00 11 24 72 ?? ?? 00 70 72 ?? ?? 00 70 11 0a 1e 5d 13 2d 12 2d 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 24 72 ?? ?? 00 70 11 16 8c 51 00 00 01 6f ?? 00 00 0a 00 11 10 11 24 6f ?? 00 00 0a 00 12 23 28 ?? 00 00 0a 13 25 12 23 28 ?? 00 00 0a 13 26 12 23 28 ?? 00 00 0a 13 27 1b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_EANW_2147946276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.EANW!MTB"
        threat_id = "2147946276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 39 16 9c 11 39 17 58 13 39 11 39 1f 0a 11 09 8e 69 ?? ?? ?? ?? ?? 32 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZTQ_2147948252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZTQ!MTB"
        threat_id = "2147948252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 11 04 09 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 0a 12 09 28 ?? 00 00 0a 0b 12 09 28 ?? 00 00 0a 0c 06 13 06 07 13 06 08 13 06 11 06 11 06 11 06 28 ?? 00 00 0a 13 05 03 11 04 09 11 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Noon_ZQO_2147952159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noon.ZQO!MTB"
        threat_id = "2147952159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0b 17 58 1f 25 5a 11 ?? 17 58 1f 65 5a 61 07 61 13 ?? 11 ?? 11 ?? 23 00 00 00 00 00 40 8f 40 5a 69 61 13 ?? 02 11 ?? 11 ?? 6f ?? 00 00 0a 13 ?? 04 03 6f ?? 00 00 0a 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

