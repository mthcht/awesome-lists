rule Trojan_MSIL_ABRisk_PTCR_2147897435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ABRisk.PTCR!MTB"
        threat_id = "2147897435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ABRisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 21 00 00 70 0a 28 ?? 00 00 0a 0b 00 73 43 00 00 0a 0d 09 06 6f 44 00 00 0a 6f 45 00 00 0a 0c de 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ABRisk_PTCT_2147897437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ABRisk.PTCT!MTB"
        threat_id = "2147897437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ABRisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 6f 00 00 0a 00 02 72 fd 02 00 70 72 0d 03 00 70 6f 31 00 00 06 26 20 10 27 00 00 28 ?? 00 00 0a 00 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

