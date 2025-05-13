rule Trojan_MSIL_ShellcodeRunner_KAA_2147895803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.KAA!MTB"
        threat_id = "2147895803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 fe 0c c2 04 00 00 07 fe 0c c2 04 00 00 93 28 ?? 00 00 0a 9c 00 fe 0c c2 04 00 00 17 58 fe 0e c2 04 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_SPPF_2147920004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.SPPF!MTB"
        threat_id = "2147920004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c e2 04 00 00 07 fe 0c e2 04 00 00 93 28 ?? ?? ?? 0a 9c 00 fe 0c e2 04 00 00 17 58 fe 0e e2 04 00 00 fe 0c e2 04 00 00 09 8e 69 fe 04 fe 0e e3 04 00 00 fe 0c e3 04 00 00 2d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_SK_2147922689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.SK!MTB"
        threat_id = "2147922689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 06 9a 13 07 00 7e 01 00 00 04 11 04 11 07 72 96 12 00 70 72 9a 12 00 70 6f 13 00 00 0a 1f 10 28 14 00 00 0a 9c 11 04 17 58 13 04 00 11 06 17 58 13 06 11 06 11 05 8e 69 32 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EACT_2147929132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EACT!MTB"
        threat_id = "2147929132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 07 08 02 08 18 5a 18 6f 10 00 00 0a 1f 10 28 11 00 00 0a 9c 00 08 17 58 0c 08 06 fe 04 0d 09 2d de}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_HNAB_2147930716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.HNAB!MTB"
        threat_id = "2147930716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 6a 00 68 00 79 00 74 00 76 00 72 00 76 00 72 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 52 65 61 64 41 6c 6c 42 79 74 65 73 00}  //weight: 2, accuracy: High
        $x_1_4 = {00 43 6f 70 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EACL_2147932164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EACL!MTB"
        threat_id = "2147932164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 72 01 00 00 70 02 08 18 5a 18 6f 08 00 00 0a 28 09 00 00 0a 0d 09 1f 10 28 0a 00 00 0a 13 04 06 08 11 04 d2 9c 00 08 17 58 0c 08 07 fe 04 13 07 11 07 2d cb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EAE_2147936803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EAE!MTB"
        threat_id = "2147936803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 06 08 6f 26 00 00 0a 6f 27 00 00 0a 6f 23 00 00 0a 26 08 17 58 0c 08 03 32 e5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EAG_2147936805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EAG!MTB"
        threat_id = "2147936805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 6f 10 00 00 0a 0d 7e 01 00 00 04 12 03 28 11 00 00 0a 6f 12 00 00 0a 2c 1a 06 7e 01 00 00 04 12 03 28 11 00 00 0a 6f 13 00 00 0a 28 14 00 00 0a 0a 2b 0e 06 12 03 28 11 00 00 0a 28 14 00 00 0a 0a 08 17 58 0c 08 07 6f 15 00 00 0a 32 b0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EAH_2147936806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EAH!MTB"
        threat_id = "2147936806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0c 2b 0e 03 06 16 07 6f 06 00 00 0a 08 07 6a 58 0c 02 06 16 06 8e 69 6f 07 00 00 0a 25 0b 16 30 e2 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EDJ_2147940176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EDJ!MTB"
        threat_id = "2147940176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 8f 09 00 00 01 25 71 09 00 00 01 72 49 00 00 70 08 20 80 00 00 00 5d 6f 06 00 00 0a d2 61 d2 81 09 00 00 01 08 17 58 0c 08 07 17 59 33 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeRunner_EAJ_2147941307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeRunner.EAJ!MTB"
        threat_id = "2147941307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 17 11 18 11 05 11 18 91 20 aa 00 00 00 61 20 ff 00 00 00 5f d2 9c 11 18 17 58 13 18 11 18 11 05 8e 69 3f d8 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

