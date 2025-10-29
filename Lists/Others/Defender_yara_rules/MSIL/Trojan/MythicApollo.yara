rule Trojan_MSIL_MythicApollo_AMP_2147956286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MythicApollo.AMP!MTB"
        threat_id = "2147956286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MythicApollo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 04 2b 43 73 4b 01 00 06 13 05 11 05 06 7d d1 00 00 04 11 05 09 11 04 9a 7d d0 00 00 04 11 05 7b d0 00 00 04 07 11 05 fe 06 4c 01 00 06 73 1e 02 00 0a 6f ?? ?? ?? 0a 2c 02 de 12 de 03 26 de 00 11 04 17 58 13 04 11 04 09 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

