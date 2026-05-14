rule Trojan_MSIL_ResolverRat_AB_2147969268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ResolverRat.AB!MTB"
        threat_id = "2147969268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ResolverRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 05 8e 69 42 06 00 00 00 04 38 03 00 00 00 05 8e 69 0a 03 05 16 06 6f 2b 00 00 0a 26 02 05 16 06 28 35 00 00 06 04 06 59 10 02 04 16 42 ce ff ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {28 2e 00 00 06 3a 0c 00 00 00 73 28 00 00 0a 02 28 2a 00 00 0a 2a 02 28 28 00 00 06 2a}  //weight: 5, accuracy: High
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

