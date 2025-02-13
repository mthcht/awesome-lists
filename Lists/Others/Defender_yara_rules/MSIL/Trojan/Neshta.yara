rule Trojan_MSIL_Neshta_AACX_2147849613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Neshta.AACX!MTB"
        threat_id = "2147849613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Neshta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 8e 69 17 da 13 08 16 13 09 2b 1b 11 04 11 09 09 11 09 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 d6 13 09 11 09 11 08 31 df}  //weight: 4, accuracy: Low
        $x_1_2 = "Polling_Project" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

