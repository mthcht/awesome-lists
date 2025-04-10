rule Trojan_MSIL_ASyncRAT_ZZU_2147938516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ASyncRAT.ZZU!MTB"
        threat_id = "2147938516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ASyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 6f ?? 00 00 0a 13 09 11 08 11 09 17 73 ?? 00 00 0a 13 0a 11 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 11 0a 6f ?? 00 00 0a de 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

