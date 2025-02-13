rule Trojan_MSIL_Privateloader_AMCA_2147898617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Privateloader.AMCA!MTB"
        threat_id = "2147898617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Privateloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 16 1f 10 28 ?? 00 00 0a 00 73 ?? 00 00 0a 08 09 6f ?? 00 00 0a 13 04 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 00 11 05 11 04 16 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? 00 00 0a 00 00 de}  //weight: 2, accuracy: Low
        $x_2_2 = "7QQretretretretretreKY" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

