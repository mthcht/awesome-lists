rule Trojan_MSIL_Cryptojoker_MBFV_2147903365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptojoker.MBFV!MTB"
        threat_id = "2147903365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptojoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 6f 00 75 00 69 00 77 00 65 00 73 00 2e 00 49 00 79 00 69 00 69 00 6d 00 74 00 6f 00 70 00 00 17 42 00 75 00 61 00 7a 00 73 00 6a 00 77 00 73 00 78 00 68 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

