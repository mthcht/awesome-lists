rule Trojan_MSIL_Comet_MBCD_2147846040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Comet.MBCD!MTB"
        threat_id = "2147846040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Comet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 06 11 04 9a 28 ?? 00 00 06 1f 7b 61 08 61 8c ?? 00 00 01 28 ?? 00 00 0a 13 05 72 ?? 00 00 70 11 05 11 05}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 18 59 18 6f ?? 00 00 0a 28 ?? 00 00 0a 13 05 07 11 04 11 05 28 ?? 00 00 06 9c 08 09 58 0c 11 04 17 58 13 04 11 04 06 8e 69 32 a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Comet_KAA_2147896400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Comet.KAA!MTB"
        threat_id = "2147896400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Comet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 07 02 11 07 91 09 61 07 11 04 91 61 9c 07 28 ?? 00 00 0a 11 04 07 8e b7 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 07 17 d6 13 07 11 07 11 08 31 cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

