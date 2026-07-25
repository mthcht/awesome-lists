rule Trojan_MSIL_Hollowgraph_GVB_2147974524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hollowgraph.GVB!MTB"
        threat_id = "2147974524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hollowgraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 06 11 06 16 72 41 00 00 70 a2 11 06 17 02 7b 0e 00 00 04 a2 11 06 18 72 29 00 00 70 a2 11 06 19 02 7b 0f 00 00 04 8c 12 00 00 01 a2 11 06 1a 72 53 00 00 70 a2 11 06 28 0d 00 00 0a 0b 07 28 0e 00 00 0a 73 14 00 00 0a 0c 73 12 00 00 06 0d 09 72 6b 00 00 70 7d 06 00 00 04 09 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

