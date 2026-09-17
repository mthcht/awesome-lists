rule Trojan_MSIL_Sharpkatz_AS_2147978400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sharpkatz.AS!MTB"
        threat_id = "2147978400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharpkatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 09 8f ?? 00 00 02 7b ?? 00 00 04 28 ?? 00 00 0a 11 07 6f ?? 00 00 06 11 09 8f ?? 00 00 02 7b ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 13 0a 11 07 6f ?? 00 00 06 11 07 6f ?? 00 00 06 11 09 8f ?? 00 00 02 7b ?? 00 00 04 11 0a 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

