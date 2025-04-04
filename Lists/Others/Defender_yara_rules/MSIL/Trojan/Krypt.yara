rule Trojan_MSIL_Krypt_PGK_2147937928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krypt.PGK!MTB"
        threat_id = "2147937928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 4a 09 61 54 09 17 62 09 1d 63 60 0d 00 11 09 17 58 13 09 11 09 06 8e 69 fe 04 13 0a 11 0a 2d d6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

