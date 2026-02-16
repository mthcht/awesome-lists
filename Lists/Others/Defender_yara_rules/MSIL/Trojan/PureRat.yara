rule Trojan_MSIL_PureRat_AB_2147963138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRat.AB!MTB"
        threat_id = "2147963138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {38 a6 ff ff ff 00 11 11 11 00 6f ?? 00 00 0a 17 73 0b 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 38 2e 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0e 00 fe 0c 0e 00 45 01 00 00 00 4c 00 00 00 fe 0c 0e 00 20 dc 03 00 00 3b e5 ff ff ff 38 39 00 00 00 11 02 6f ?? 00 00 0a 38 00 00 00 00 11 11 6f ?? 00 00 0a 73 0f 00 00 0a 13 03 20 04 00 00 00 7e 4d 00 00 04 7b 47 00 00 04 3a b6 ff ff ff 26 20}  //weight: 6, accuracy: Low
        $x_2_2 = "FromBase64String" ascii //weight: 2
        $x_2_3 = "TripleDESCryptoServiceProvider" ascii //weight: 2
        $x_2_4 = "GZipStream" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

