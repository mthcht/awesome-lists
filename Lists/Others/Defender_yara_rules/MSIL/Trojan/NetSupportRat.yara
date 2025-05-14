rule Trojan_MSIL_NetSupportRat_ANR_2147941428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetSupportRat.ANR!MTB"
        threat_id = "2147941428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetSupportRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 33 02 de 46 06 28 ?? 00 00 0a 26 06 28 ?? 00 00 06 26 72 ?? 00 00 70 28 ?? 00 00 06 0d 09 2c 04 09 8e ?? 02 de 24 09 06 28 ?? 00 00 06 06 28}  //weight: 2, accuracy: Low
        $x_5_2 = "185.149.146.73" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

