rule Trojan_MSIL_Searaph_AMAA_2147852133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Searaph.AMAA!MTB"
        threat_id = "2147852133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Searaph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 06 1a 58 4a 08 8e 69 5d 91 07 06 1a 58 4a 91 61 d2 6f ?? 00 00 0a 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 07 8e 69 32 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

