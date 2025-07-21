rule Trojan_MSIL_PureLogs_SK_2147903203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SK!MTB"
        threat_id = "2147903203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 8d 17 00 00 01 13 05 11 04 11 05 16 09 6f 13 00 00 0a 26 11 05 28 01 00 00 2b 28 02 00 00 2b 0a de 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SL_2147914284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SL!MTB"
        threat_id = "2147914284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 57 00 00 04 06 07 03 6f 2a 00 00 0a 0c 08 2c 0f 07 08 58 0b 03 08 59 fe 0b 01 00 03 16 30 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_KAF_2147917510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.KAF!MTB"
        threat_id = "2147917510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 95 61 28 ?? 00 00 0a 9c fe 0c 06 00 20 ?? 00 00 00 6a 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SN_2147917691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SN!MTB"
        threat_id = "2147917691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 72 01 00 00 70 20 00 01 00 00 14 14 14 6f 18 00 00 0a 26 de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_ZZV_2147938550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.ZZV!MTB"
        threat_id = "2147938550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 20 9f 22 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 20 c6 22 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c de 12}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_ZXY_2147938680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.ZXY!MTB"
        threat_id = "2147938680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 20 00 00 00 00 38 ?? ff ff ff 11 00 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 03 20 02 00 00 00 7e ?? 02 00 04 7b ?? 02 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SP_2147939554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SP!MTB"
        threat_id = "2147939554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 09 11 04 11 05 08 11 05 59 6f 12 00 00 0a 58 13 05 11 05 08 32 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_ZDV_2147941136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.ZDV!MTB"
        threat_id = "2147941136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0b de 73 20 cc 56 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0c 20 b6 54 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 03 20 a3 54 00 00 28 ?? 00 00 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 de 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_ZDU_2147941985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.ZDU!MTB"
        threat_id = "2147941985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 37 2b 39 15 2d 39 26 26 2b 3c 2b 3e 2b 3f 11 04 6f ?? 00 00 0a 13 05 72 13 01 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 07 03 11 06 28 ?? 00 00 06 de 28 11 04 2b c5 08 2b c4 6f ?? 00 00 0a 2b c2 11 04 2b c0 09 2b bf 6f ?? 00 00 0a 2b ba}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SQ_2147944617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SQ!MTB"
        threat_id = "2147944617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 02 08 91 03 08 07 5d 6f 0b 00 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SR_2147944618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SR!MTB"
        threat_id = "2147944618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 0c 00 00 06 0a dd 0e 00 00 00 26 dd 00 00 00 00 08 17 58 0c 08 07 32 e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SS_2147944878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SS!MTB"
        threat_id = "2147944878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0c 00 00 06 0a dd 18 00 00 00 26 20 88 13 00 00 28 0f 00 00 0a dd 00 00 00 00 08 17 58 0c 08 07 32 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_AB_2147944987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.AB!MTB"
        threat_id = "2147944987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 72 00 00 04 20 17 40 9b c0 20 a5 ee 07 95 61 20 60 7d 1a 23 61 7d 78 00 00 04 20 40 00 00 00 38 8c ec ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_AC_2147945020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.AC!MTB"
        threat_id = "2147945020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 29 03 00 04 20 4d a0 de 9b 20 ad eb 60 bd 58 20 fa 8b 3f 59 61 7d 2b 03 00 04 20 2f 00 00 00 fe 0e 00 00 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_ST_2147945219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.ST!MTB"
        threat_id = "2147945219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 3a 1a 00 00 00 73 04 00 00 0a 72 01 00 00 70 73 05 00 00 0a 28 06 00 00 0a 6f 07 00 00 0a 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 08 00 00 0a dd 13 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SU_2147945354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SU!MTB"
        threat_id = "2147945354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 28 0b 00 00 0a 0b 0f 02 28 0c 00 00 0a 39 07 00 00 00 16 0c dd 33 00 00 00 07 03 04 05 6f 03 00 00 06 3a 07 00 00 00 16 0c dd 1e 00 00 00 12 00 28 0d 00 00 0a 2d c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_BAA_2147945620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.BAA!MTB"
        threat_id = "2147945620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 73 14 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 1b 00 00 0a 13 05 38 00 00 00 00 00 73 0b 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 07 38 00 00 00 00 dd 55 ff ff ff 11 06 39 11 00 00 00 38 00 00 00 00 11 06 ?? ?? 00 00 0a 38 00 00 00 00 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SV_2147945963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SV!MTB"
        threat_id = "2147945963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 05 00 00 0a 72 01 00 00 70 73 06 00 00 0a 28 07 00 00 0a 6f 08 00 00 0a 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 09 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SW_2147946017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SW!MTB"
        threat_id = "2147946017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {38 0c 00 00 00 12 00 28 06 00 00 0a 6f 0a 00 00 06 12 00 28 07 00 00 0a 2d eb dd 0e 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SX_2147946160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SX!MTB"
        threat_id = "2147946160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 05 16 11 05 8e 69 6f 0f 00 00 0a 25 13 06 16 3d 0f 00 00 00 38 1b 00 00 00 38 df ff ff ff 38 00 00 00 00 11 01 11 05 16 11 06 6f 10 00 00 0a 38 c9 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_BAB_2147946310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.BAB!MTB"
        threat_id = "2147946310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 73 07 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 08 00 00 0a 13 05 38 00 00 00 00 00 73 09 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 07 38 00 00 00 00 dd 82 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_BAC_2147946315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.BAC!MTB"
        threat_id = "2147946315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 0b 00 00 0a 7a 11 00 16 73 0d 00 00 0a 13 04 38 00 00 00 00 00 20 00 10 00 00 8d 0d 00 00 01 13 05 38 2d 00 00 00 11 04 11 05 16 11 05 8e 69 ?? ?? 00 00 0a 25 13 06 16 3d 05 00 00 00 38 1b 00 00 00 11 01 11 05 16 11 06 ?? ?? 00 00 0a 38 d3 ff ff ff 38 ce ff ff ff 38 e5 ff ff ff dd 41 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SY_2147946851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SY!MTB"
        threat_id = "2147946851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 2d 00 00 0a 25 6f 2e 00 00 0a 72 51 01 00 70 72 67 01 00 70 6f 2f 00 00 0a 25 72 5e 02 00 70 6f 30 00 00 0a 0a 6f 31 00 00 0a dd 09 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SZ_2147946868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SZ!MTB"
        threat_id = "2147946868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 2d 00 00 0a 25 6f 2e 00 00 0a 72 51 01 00 70 72 67 01 00 70 6f 2f 00 00 0a 25 72 06 02 00 70 6f 30 00 00 0a 0a 6f 31 00 00 0a dd 09 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SA_2147947055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SA!MTB"
        threat_id = "2147947055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 2d 00 00 0a 25 6f 2e 00 00 0a 72 51 01 00 70 72 67 01 00 70 6f 2f 00 00 0a 25 72 52 02 00 70 6f 30 00 00 0a 0a 6f 31 00 00 0a dd 09 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

