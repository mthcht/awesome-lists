rule Trojan_MSIL_ozirp_RDF_2147893867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ozirp.RDF!MTB"
        threat_id = "2147893867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ozirp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 2f 00 00 0a 6f 33 00 00 0a 25 17 6f 34 00 00 0a 25 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

