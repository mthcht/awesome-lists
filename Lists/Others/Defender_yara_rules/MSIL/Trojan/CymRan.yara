rule Trojan_MSIL_CymRan_ACY_2147896957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRan.ACY!MTB"
        threat_id = "2147896957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 2b 1f 00 08 09 9a 28 ?? 00 00 0a 28 ?? 00 00 06 13 04 11 04 2c 06 00 06 17 58 0a 00 00 09 17 58 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {08 11 06 9a 28 ?? 00 00 0a 6f ?? 00 00 06 00 08 11 06 9a 28 ?? 00 00 06 13 08 11 08 2c 06 00 07 17 58 0b 00 00 00 11 06 17 58 13 06 11 06 08 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CymRan_ACA_2147896975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRan.ACA!MTB"
        threat_id = "2147896975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 16 16 6f ?? 00 00 0a 0a 06 2c 05 00 16 0b de 0b 00 17 0b de 06 26 00 17 0b de 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 fe 01 0c 08 2c 61 00 02 28 ?? 00 00 0a 0d 09 2c 51 00 00 02 73 ?? 00 00 0a 03 04 05 28 ?? 00 00 0a 25 0a 13 04 00 06 16 6a 16 6a 6f ?? 00 00 0a 00 00 06 16 6a 16 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CymRan_ADT_2147934002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRan.ADT!MTB"
        threat_id = "2147934002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {14 0a 16 0b 02 28 ?? 00 00 0a 2d 47 02 28 ?? 00 00 0a 2c 3d 02 73 79 00 00 0a 03 04 05 28 ?? 00 00 0a 25 0a 0c 06 16 6a 16 6a 6f ?? 00 00 0a 06 16 6a 16 6a 6f ?? 00 00 0a de 03 26 de 00 de 0a 08 2c 06 08}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 10 00 00 01 25 16 02 7b 1d 00 00 04 a2 25 17 02 7b 19 00 00 04 a2 25 18 06 a2 25 19 28 ?? 00 00 0a a2 28}  //weight: 2, accuracy: Low
        $x_4_3 = "TamirAbuSalah\\source\\repos\\cymulate-scenario-generator\\Executors\\CymulateTaskScheduler\\CymulateTaskScheduler\\obj\\Release\\EDRTaskScheduler.pdb" ascii //weight: 4
        $x_1_4 = "EDR stops running" wide //weight: 1
        $x_1_5 = "CymulateEDR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CymRan_ACN_2147934027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRan.ACN!MTB"
        threat_id = "2147934027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 07 2b 3a 06 6f ?? 00 00 0a 13 08 09 11 08 d2 6e 00 72 5a 17 00 70 28 ?? 00 00 0a 11 07 5a 00 72 5e 17 00 70 28 ?? 00 00 0a 5f 62 60 0d 11 07 00 72 29 00 00 70 28 ?? 00 00 0a 58 13 07 11 07}  //weight: 2, accuracy: Low
        $x_3_2 = {64 d2 9c 11 07 11 05 25 00 72 29 00 00 70 28 ?? 00 00 0a 58 13 05 11 0b 00 72 e2 1a 00 70 28 ?? 00 00 0a 64 d2 9c 08 11 0a 8f 61 00 00 01 25 4b 11 0b 61 54 11 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

