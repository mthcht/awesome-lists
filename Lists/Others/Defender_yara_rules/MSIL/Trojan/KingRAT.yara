rule Trojan_MSIL_KingRAT_PLIDH_2147931168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KingRAT.PLIDH!MTB"
        threat_id = "2147931168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KingRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 06 08 6f ?? 00 00 0a 11 06 18 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 02 7e ?? 00 00 04 07 20 ad 01 00 00 59 97 29 ?? 00 00 11 0a 11 07 06 16 06 8e 20 4e 12 d7 6b 80 ?? 00 00 04 b7 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 11 05 13 08 00 20 e1 2a 79 2f 80 ?? 00 00 04 11 08 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

