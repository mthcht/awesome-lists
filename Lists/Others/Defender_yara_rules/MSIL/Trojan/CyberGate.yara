rule Trojan_MSIL_CyberGate_NE_2147830089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CyberGate.NE!MTB"
        threat_id = "2147830089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 17 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 7e 15 00 00 04 28 ?? 00 00 0a 28 ?? 00 00 06 80 18 00 00 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CyberGate_EM_2147847117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CyberGate.EM!MTB"
        threat_id = "2147847117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {d6 20 00 01 00 00 5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 03 50 11 0a 03 50 11 0a 91 11 05 08 91 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CyberGate_ACG_2147894251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CyberGate.ACG!MTB"
        threat_id = "2147894251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0b 2b 4c 16 13 04 2b 37 03 11 04 07 6f ?? 00 00 0a 0a 08 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 08 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 08 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 17 d6 13 04 11 04 03 6f ?? 00 00 0a 17 da 31 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CyberGate_KAA_2147898342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CyberGate.KAA!MTB"
        threat_id = "2147898342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 09 91 07 1f 1f 5f 62 09 28 ?? 00 00 06 08 58 13 04 06 08 06 08 91 11 04 28 ?? 00 00 06 d2 9c 09 17 58 0d 09 03 8e 69 32 d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CyberGate_KPAA_2147907709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CyberGate.KPAA!MTB"
        threat_id = "2147907709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyberGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 15 31 0c 07 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 28 ?? ?? 00 0a 07 6f ?? ?? 00 0a 0d 07 2c 26}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

