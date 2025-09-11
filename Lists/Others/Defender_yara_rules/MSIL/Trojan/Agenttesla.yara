rule Trojan_MSIL_Agenttesla_PAL_2147787188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PAL!MTB"
        threat_id = "2147787188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 11 1e 1f 11 5a 58 13 1f 00 02 11 1d 11 1e 6f ?? 00 00 0a 13 20 04 03 6f ?? 00 00 0a 59 13 21 11 21 13 22 11 22 19 fe 02 13 28 11 28 2c 03}  //weight: 5, accuracy: Low
        $x_5_2 = {11 0c 16 5f 13 23 11 23 19 5d 13 24 17 11 23 58 19 5d 13 25 18 11 23 58 19 5d 13 26 19}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_XNHU_2147805871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.XNHU!MTB"
        threat_id = "2147805871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$0724365f-09b1-41e0-a65b-c39070c11cf4" ascii //weight: 10
        $x_1_2 = "duckchoiceselector" ascii //weight: 1
        $x_1_3 = "ducknamevariables" ascii //weight: 1
        $x_1_4 = "Generateduckcode" ascii //weight: 1
        $x_1_5 = "Gimmeaduck" ascii //weight: 1
        $x_1_6 = "integrate" ascii //weight: 1
        $x_1_7 = "reader" ascii //weight: 1
        $x_1_8 = "regenerate" ascii //weight: 1
        $x_1_9 = "uniqueDuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_EVD_2147821516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.EVD!MTB"
        threat_id = "2147821516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 14 ed f4 d5 0d 87 c3 37 07 d6 21 e1 cd e6 e7 d3 fb c8 d8 a1 e6 81 02 44 14 53 d6 2f 10 5d e9 b6 c7 aa 26 5e 5a 51 c0 40 b3 40 f6 1e 25 62 49}  //weight: 1, accuracy: High
        $x_1_2 = {d8 fd 46 95 01 a8 30 46 13 47 87 c6 2a f5 7c 0f af c1 bd ce ee 24 20 70 db e8 c7 b7 56 d7 6a a4 78 cd f2 14 ba ba 8b 5c da d4 49 b7 7c 01 52 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_EVB_2147822269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.EVB!MTB"
        threat_id = "2147822269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 07 11 04 16 11 05 6f ?? ?? ?? 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d8}  //weight: 1, accuracy: Low
        $x_1_2 = "Start-Sleep -Seconds 18" wide //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_EVL_2147822271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.EVL!MTB"
        threat_id = "2147822271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 12 01 11 04 11 05 28 ?? ?? ?? 06 00 00 11 05 16 fe 02 13 06 11 06 2d d8}  //weight: 1, accuracy: Low
        $x_1_2 = "Start-Sleep -Seconds 9;Start-Sleep -Seconds 9;" wide //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_EVC_2147826545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.EVC!MTB"
        threat_id = "2147826545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 07 17 da 28 ?? ?? ?? 06 28 ?? ?? ?? 06 11 04 11 07 11 04 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 28 ?? ?? ?? 06 da}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "String1" wide //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAD_2147900084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAD!MTB"
        threat_id = "2147900084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 03 07 91 04 07 04 8e 69 5d 91 61 b4 9c 07 17 d6 0b 07 03 8e 69 32 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAD_2147900084_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAD!MTB"
        threat_id = "2147900084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 05 11 04 5d 13 08 11 05 1f 16 5d 13 09 11 05 17 58 11 04 5d 13 0a 07 11 08 91 08 11 09 91 61 13 0b 20 00 01 00 00 13 0c 11 0b 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0e 11 0e 2d a9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAD_2147900084_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAD!MTB"
        threat_id = "2147900084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 0d 06 17 58 13 0a 06 20 00 b6 00 00 5d 13 04 11 0a 20 00 b6 00 00 5d 13 0b 07 11 0b 91 09 58 13 0c 07 11 04 91 13 0d 11 06 06 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 04 11 0f 11 0c 59 09 5d d2 9c 06 17 58 0a 06 20 00 b6 00 00 fe 04 13 10 11 10 2d a6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAE_2147900124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAE!MTB"
        threat_id = "2147900124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 56 01 00 5d 13 0a 11 09 20 00 56 01 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 5d d2 9c 00 11 07 17 58 13 07 11 07 20 00 56 01 00 fe 04 13 10 11 10 2d 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAF_2147900317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAF!MTB"
        threat_id = "2147900317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 32 01 00 5d 13 09 11 08 20 00 32 01 00 5d 13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c 11 06 17 58 13 06 11 06 20 00 32 01 00 32 a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAG_2147900318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAG!MTB"
        threat_id = "2147900318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 90 01 00 5d 13 0a 11 09 20 00 90 01 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 5d d2 9c 00 11 07 17 58 13 07 11 07 20 00 90 01 00 fe 04 13 10 11 10 2d 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAH_2147900319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAH!MTB"
        threat_id = "2147900319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 90 01 00 5d 13 0a 11 09 20 00 90 01 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 5d d2 9c 11 07 17 58 13 07 11 07 20 00 90 01 00 32 a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAI_2147900422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAI!MTB"
        threat_id = "2147900422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 06 01 00 5d 13 09 11 08 20 00 06 01 00 5d 13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c 11 06 17 58 13 06 11 06 20 00 06 01 00 32 a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAJ_2147900669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAJ!MTB"
        threat_id = "2147900669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 18 11 17 17 58 13 19 11 17 20 00 ba 00 00 5d 13 1a 11 19 20 00 ba 00 00 5d 13 1b 08 11 1a 91 13 1c 09 11 17 1f 16 5d 91 13 1d 08 11 1b 91 11 18 58 13 1e 11 1c 11 1d 61 13 1f 11 1f 11 1e 59 13 20 08 11 1a 11 20 11 18 5d d2 9c 00 11 17 17 58 13 17 11 17 20 00 ba 00 00 fe 04 13 21 11 21 2d 98}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAJ_2147900669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAJ!MTB"
        threat_id = "2147900669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 07 91 0c 03 07 03 8e 69 5d 91 0d 16 13 04 16 13 05 2b 41 00 08 17 11 05 1f 1f 5f 62 5f 16 fe 03 13 06 09 17 11 05 1f 1f 5f 62 5f 16 fe 03 13 07 11 06 11 07 61 13 08 11 08 13 09 11 09 2c 0e 11 04 17 11 05 1f 1f 5f 62 d2 60 d2 13 04 00 11 05 17 58 13 05 11 05 1e fe 04 13 0a 11 0a 2d b4 06 07 11 04 9c 00 07 17 58 0b 07 02 8e 69 fe 04 13 0b 11 0b 2d 89}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAK_2147900811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAK!MTB"
        threat_id = "2147900811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 9a 01 00 5d 13 09 11 08 20 00 9a 01 00 5d 13 0a 07 11 09 91 13 0b 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 11 06 1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 11 0b 11 0c 61 13 0e 11 0e 11 0d 59 13 0f 07 11 09 11 0f 11 07 5d d2 9c 00 11 06 17 58 13 06 11 06 20 00 9a 01 00 fe 04 13 10 11 10 2d 87}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAN_2147900818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAN!MTB"
        threat_id = "2147900818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 13 04 09 17 58 09 20 00 9a 01 00 5d 13 05 20 00 9a 01 00 5d 13 06 07 11 05 91 13 07 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 09 1f 16 5d 91 13 08 07 11 06 91 11 04 58 13 09 11 07 11 08 61 11 09 59 13 0a 07 11 05 11 0a 11 04 5d d2 9c 09 17 58 0d 09 20 00 9a 01 00 32 9d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_ARAQ_2147900889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.ARAQ!MTB"
        threat_id = "2147900889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 07 5d 13 0b 11 04 11 0b 91 11 05 11 08 1f 16 5d 91 61 13 0c 11 0c 11 04 11 08 17 58 11 07 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0d 11 04 11 0b 11 0d d2 9c 11 08 17 58 13 08 11 08 11 07 11 06 17 58 5a 32 b5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PPGH_2147921873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PPGH!MTB"
        threat_id = "2147921873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 12 01 28 7b 00 00 0a 6f ?? 00 00 0a 00 09 18 fe 04 16 fe 01 13 06 11 06 2c 0e 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 19 fe 01 13 07 11 07 2c 0e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PPMH_2147923244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PPMH!MTB"
        threat_id = "2147923244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGA_2147942842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGA!MTB"
        threat_id = "2147942842"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 05 0e 04 6f ?? 00 00 0a 0a 06 0e 05 28 ?? 00 00 06 0b 04 03 6f ?? 00 00 0a 59 0c 08 19 32 0a 03 07 0e 05 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGA_2147942842_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGA!MTB"
        threat_id = "2147942842"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 72 33 00 00 70 28 ?? 00 00 06 72 4d 00 00 70 72 99 00 00 70}  //weight: 4, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 69 00 61 00 2e 00 74 00 66 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGY_2147943194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGY!MTB"
        threat_id = "2147943194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 35 00 2e 00 38 00 37 00 2e 00 36 00 30 00 2e 00 31 00 32 00 37 00 2f 00 77 00 61 00 79 00 2f 00 [0-64] 2e 00}  //weight: 5, accuracy: Low
        $x_5_2 = {68 00 74 00 74 00 70 00 3a 00 2f 2f 34 35 2e 38 37 2e 36 30 2e 31 32 37 2f 77 61 79 2f [0-64] 2e}  //weight: 5, accuracy: Low
        $x_5_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 69 00 61 00 2e 00 74 00 66 00 2f 00 [0-64] 2e 00}  //weight: 5, accuracy: Low
        $x_5_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 2f 63 69 61 2e 74 66 2f [0-64] 2e}  //weight: 5, accuracy: Low
        $x_1_5 = ".pdf" ascii //weight: 1
        $x_1_6 = ".wav" ascii //weight: 1
        $x_1_7 = ".vdf" ascii //weight: 1
        $x_1_8 = ".mp4" ascii //weight: 1
        $x_5_9 = {28 04 00 00 06 72 01 00 00 70 72 33 00 00 70 28 05 00 00 06 72 4d 00 00 70 72 99 00 00 70 28 06 00 00 06 20 00 00 00 00 7e ?? ?? 00 04 7b ?? ?? 00 04 ?? 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c ?? 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Agenttesla_PGAT_2147945221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGAT!MTB"
        threat_id = "2147945221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 11 1c 11 0c 6f ?? ?? 00 0a 23 00 00 00 00 00 00 59 40 5a a1 11 09 11 1c 11 0c 6f ?? ?? 00 0a 23 00 00 00 00 00 00 24 40 5a 23 00 00 00 00 00 00 14 40 59 a1 11 1c 17 d6 13 1c 11 1c 11 1b 31 be}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGAT_2147945221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGAT!MTB"
        threat_id = "2147945221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 1a 1f 11 5a 11 19 1f 1f 5a 58 11 0b 20 ?? ?? 00 00 6f ?? 00 00 0a 61 13 1b 11 19 1f 13 5a 11 1a 1f 17 5a 58 11 0b 20 ?? ?? 00 00 6f ?? 00 00 0a 61 13 1c 11 1a 11 19 61 20 ?? 00 00 00 5f 13 1d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGAC_2147948463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGAC!MTB"
        threat_id = "2147948463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 fe 02 13 04 11 04 2c 13 02 7b ?? 00 00 04 12 01 28 ?? 00 00 0a 6f ?? ?? 00 0a 00 08 17 59 25 0c 16 fe 02 13 05 11 05 2c 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGAC_2147948463_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGAC!MTB"
        threat_id = "2147948463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 09 11 09 2c 05 07 1f 63 58 0b 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 13 0a 11 0a 2c 02 2b 41 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 13 0b 11 0b 2c 02 2b 21 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 38 1e ff ff ff 08 17 58 0c 16 0a 38 13 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGAG_2147949290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGAG!MTB"
        threat_id = "2147949290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8c 07 00 00 1b 03 04 05 6f ?? ?? 00 0a 06 17 58 0a 0e 05 25 5a 0e 05 58 18 5d 2c 0e 11 04 20 76 01 00 00 91 0c 38 67 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGAR_2147950675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGAR!MTB"
        threat_id = "2147950675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 0b 11 0d 6f ?? 00 00 0a 13 0e 04 03 6f ?? 00 00 0a 59 13 0f 11 0f 13 10 11 10 19 fe 02 13 16 11 16 2c 03 19 13 10 11 10 16 fe 04 13 17 11 17 2c 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agenttesla_PGBA_2147951190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenttesla.PGBA!MTB"
        threat_id = "2147951190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfq" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

