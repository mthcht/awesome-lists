rule Trojan_MSIL_Orcus_KAA_2147896397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Orcus.KAA!MTB"
        threat_id = "2147896397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Orcus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 5, accuracy: Low
        $x_5_2 = {36 00 34 00 38 00 36 00 2e 00 32 00 2e 00 2e 00 46 00 36 00 35 00 32 00 2e 00 32 00 41 00 37}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

