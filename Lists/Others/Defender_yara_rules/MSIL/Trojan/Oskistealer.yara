rule Trojan_MSIL_Oskistealer_AOS_2147901501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Oskistealer.AOS!MTB"
        threat_id = "2147901501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Oskistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 28 07 00 00 06 58 0c 08 06 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Oskistealer_AOS_2147901501_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Oskistealer.AOS!MTB"
        threat_id = "2147901501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Oskistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 06 11 04 9a 28 ?? 00 00 06 13 05 07 11 04 11 05 28 ?? 00 00 06 74 ?? 00 00 1b a2 09 07 11 04 9a 8e 69 58}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 2c 26 07 8d ?? 00 00 01 0c 7e ?? 00 00 04 0d 2b 11 02 03 08 09 28 ?? 00 00 06 09 7e ?? 00 00 04 58 0d 09 07 32 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Oskistealer_AIS_2147903156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Oskistealer.AIS!MTB"
        threat_id = "2147903156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Oskistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0a 18 0b 06 6f ?? 00 00 0a 07 9a 0c 08 6f ?? 00 00 0a 07 17 58 25 0b 9a 0d 09 14 02 28}  //weight: 2, accuracy: Low
        $x_1_2 = "MonopolySimulator" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

