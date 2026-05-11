rule Trojan_MSIL_Pterodo_ZND_2147968976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pterodo.ZND!MTB"
        threat_id = "2147968976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pterodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 07 06 07 91 04 1f 1f 5f 63 06 07 91 1e 04 59 1f 1f 5f 62 60 20 ff 00 00 00 5f d2 9c 06 07 06 07 91 03 07 04 5a 58 61 d2 9c 07 17 58 0b 07 06 8e 69 32 cc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

