rule Trojan_MSIL_SystemBC_2147840831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.psyA!MTB"
        threat_id = "2147840831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {07 9a 06 28 82 00 00 0a 39 0b 00 00 00 7e ad 04 00 04 74 71 00 00 01 2a 07 17 58 0b 07 7e ac 04 00 04 8e}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_2147840831_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.psyA!MTB"
        threat_id = "2147840831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {72 5b 00 00 70 28 08 00 00 0a 19 6f 09 00 00 0a 28 17 00 00 0a 8c 14 00 00 01 28 18 00 00 0a 28 03 00 00 06 25 28 19 00 00 0a 28 1a 00 00 0a 72 b7 00 00 70 6f 1b 00 00 0a 72 c7 00 00 70 20 00 01 00 00 14 14 17 8d 01 00 00 01 25 16 02 a2 6f 1c 00 00 0a 26 de 07}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_2147840832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.psyE!MTB"
        threat_id = "2147840832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "psyE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {d4 73 23 cd c7 f7 e2 fc ed 7e d9 d2 64 e3 18 b5 1a a7 3f 8a bf a6 75 e0 2c 3a 29 28 df 78 52 65}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_2147840840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.psyN!MTB"
        threat_id = "2147840840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "psyN: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {02 28 1c 00 00 0a 02 1f 2a 7d 02 00 00 04 02 72 0d 00 00 70 7d 03 00 00 04 2a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_2147844901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.psyZ!MTB"
        threat_id = "2147844901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "psyZ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {06 fe 06 15 00 00 0a 29 0f 00 00 11 72 01 00 00 70 fe 06 16 00 00 0a 29 10 00 00 11 2c 04 17 0b de 04}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_SPRG_2147915833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.SPRG!MTB"
        threat_id = "2147915833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d2 13 30 11 0e 1e 63 d1 13 0e 11 18 11 09 91 13 20 11 18 11 09 11 20 11 28 61 11 1c 19 58 61 11 30 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_SARA_2147920485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.SARA!MTB"
        threat_id = "2147920485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 73 0d 00 00 0a 0d 09 08 17 73 0e 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 0a de 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_BJ_2147928355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.BJ!MTB"
        threat_id = "2147928355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 09 07 08 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0a de 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_AKGA_2147928428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.AKGA!MTB"
        threat_id = "2147928428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 09 07 08 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0a de 18}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_ATGA_2147928627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.ATGA!MTB"
        threat_id = "2147928627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 20 00 01 00 00 6f ?? 00 00 0a 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04}  //weight: 4, accuracy: Low
        $x_2_2 = {2b 0f 2b 11 1e 2d 12 26 26 2b 15 2b 17 2b 1c de 62 11 06 2b ed 11 04 2b eb 6f ?? 00 00 0a 2b e9 11 04 2b e7 6f ?? 00 00 0a 2b e2 13 07 2b e0}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SystemBC_GKN_2147931006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemBC.GKN!MTB"
        threat_id = "2147931006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 56 bc 11 d2 20 be 6a e4 15 61 20 06 62 4a 18 58 65 20 75 06 9b 05 58 65 20 10 32 a5 da 59 65 66 61 fe 09 00 00 61 d1 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

