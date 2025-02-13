rule Trojan_MSIL_Coinstealer_KAL_2147903247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coinstealer.KAL!MTB"
        threat_id = "2147903247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 02 de 29 06 28 ?? 00 00 06 0b 12 01 28 ?? 00 00 0a 2d 02 de 17 07 06 28 ?? 00 00 06 de 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

