rule Backdoor_MSIL_Androm_MR_2147782775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.MR!MTB"
        threat_id = "2147782775"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 50 09 03 50 8e 69 6a 5d b7 03 50 09 03 50 8e 69 6a 5d b7 91 07 09 07 8e 69 6a 5d b7 91 61 03 50 09 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_ABD_2147830989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.ABD!MTB"
        threat_id = "2147830989"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 1f 10 07 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 08 1f 10 07 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59 8d ?? ?? ?? 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 1f 10 58 1f 10 59 28 ?? ?? ?? 0a 00 11 04}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "ParseFailure" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "RayCastGame.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_EAM_2147843767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.EAM!MTB"
        threat_id = "2147843767"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 01 2a 00 72 01 02 00 70 28 ?? 00 00 06 18 3a ?? 00 00 00 26 38 00 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 1a 3a ?? 00 00 00 26 38 00 00 00 00 dd ?? ff ff ff 13 00 38 00 00 00 00 38}  //weight: 3, accuracy: Low
        $x_2_2 = "downloadserver.duckdns.org/SystemEnv/uploads/Newiter_Bdgdwfsw.png" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_EAN_2147845506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.EAN!MTB"
        threat_id = "2147845506"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 73 10 00 00 06 25 07 28 ?? 00 00 06 6f ?? 00 00 06 0c dd ?? 00 00 00 26 de c9}  //weight: 2, accuracy: Low
        $x_1_2 = "conv.ovf.u4" wide //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_PSA_2147847922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.PSA!MTB"
        threat_id = "2147847922"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 11 05 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d db}  //weight: 1, accuracy: Low
        $x_1_2 = "transmissionLine1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KA_2147851485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KA!MTB"
        threat_id = "2147851485"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 50 06 91 1c 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KAAC_2147852102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KAAC!MTB"
        threat_id = "2147852102"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 04 11 08 58 11 07 11 09 58 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_ASCC_2147852318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.ASCC!MTB"
        threat_id = "2147852318"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 11 05 11 0a 75 ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 1f 09 13 0e 38 ?? fe ff ff 11 09 17 58 13 09 1f 0c 13 0e 38}  //weight: 4, accuracy: Low
        $x_1_2 = "b68104feb5775bdb07559a52a4d5ee8e.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KAAD_2147852434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KAAD!MTB"
        threat_id = "2147852434"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 56 09 08 6f ?? 00 00 0a 5d 13 06 09 08 6f ?? 00 00 0a 5b 13 07 08 72 ?? ?? ?? ?? 18 18 8d ?? 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 25 17 11 07 8c ?? 00 00 01 a2 28 ?? 00 00 0a a5 ?? 00 00 01 13 08 12 08 28 ?? 00 00 0a 13 09 07 11 09 6f ?? 00 00 0a 09 17 58 0d 09 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 5a 32 9a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_AAUK_2147894399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.AAUK!MTB"
        threat_id = "2147894399"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 fd 00 91 87 2b d0 02 02 7b ?? 00 00 04 06 6f ?? 00 00 06 7d ?? 00 00 04 20 fc 00 91 87 2b b7 02 7b ?? 00 00 04 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a 20 fe 00 91 87 2b 9a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_GNW_2147895480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.GNW!MTB"
        threat_id = "2147895480"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 18 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 03 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 08 06 16 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 2b 00 09 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "po-proj.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KAAB_2147896232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KAAB!MTB"
        threat_id = "2147896232"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 08 11 04 07 11 04 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 05 11 05 2d d4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KAAE_2147896404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KAAE!MTB"
        threat_id = "2147896404"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 36 00 2d 00 32 00 34 00 2d 00 31 00 35 00 2d 00 34 00 36 00 2d 00 31 00 34 00 2d 00 31 00 35 00 2d 00 37 00 34 00 2d}  //weight: 1, accuracy: High
        $x_1_2 = "NavigationLib.Form1.resources" ascii //weight: 1
        $x_1_3 = "StringBuilder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_BBAA_2147900888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.BBAA!MTB"
        threat_id = "2147900888"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 12 01 1f 20 28 ?? 00 00 2b 00 06 07 6f ?? 00 00 0a 00 06 1f 10 8d ?? 00 00 01 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 02 19 73 ?? 00 00 0a 0d 03 18 73 ?? 00 00 0a 13 04 09 08 16 73 ?? 00 00 0a 13 05 00 11 05 11 04 6f ?? 00 00 0a 00 00 de 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KAAF_2147901160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KAAF!MTB"
        threat_id = "2147901160"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 11 07 11 01 94 11 07 11 03 94 58 20 00 ?? 00 00 5d 94 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_E_2147920482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.E!MTB"
        threat_id = "2147920482"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 10 00 dd}  //weight: 3, accuracy: Low
        $x_2_2 = {11 04 72 01 00 00 70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 dd 06 00 00 00 26 dd 00 00 00 00 09 17 58 0d 09 08 8e 69 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_SK_2147923168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.SK!MTB"
        threat_id = "2147923168"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 08 6f 5a 00 00 0a 11 07 18 6f 5b 00 00 0a 1f 10 28 5c 00 00 0a 28 5d 00 00 0a 16 91 13 08 09 11 08 6f 5e 00 00 0a 00 00 11 07 18 58 13 07 11 07 08 6f 5a 00 00 0a 6f 56 00 00 0a fe 04 13 09 11 09 2d bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_SL_2147925355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.SL!MTB"
        threat_id = "2147925355"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 06 5a 03 5d 17 fe 01 0b 07 39 08 00 00 00 00 06 0c 38 18 00 00 00 00 06 17 58 0a 06 03 fe 04 0d 09 2d db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_KAAI_2147929226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.KAAI!MTB"
        threat_id = "2147929226"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 07 09 07 8e 69 5d 91 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_AKKA_2147936387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.AKKA!MTB"
        threat_id = "2147936387"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 8d 19 00 00 01 13 04 16 13 05 38 1b 00 00 00 11 04 11 05 06 11 05 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 05 17 58 13 05 11 05 06 8e 69 32 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Androm_AFLA_2147936389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Androm.AFLA!MTB"
        threat_id = "2147936389"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 06 38 1b 00 00 00 11 05 11 06 06 11 06 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 06 17 58 13 06 11 06 06 8e 69 32 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

