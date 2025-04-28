rule Trojan_MSIL_marsilia_SWC_2147940145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/marsilia.SWC!MTB"
        threat_id = "2147940145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1e 8d 09 00 00 01 0c 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 16 08 16 1e 28 ?? 00 00 0a 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 28 ?? 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 dd 0d 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

