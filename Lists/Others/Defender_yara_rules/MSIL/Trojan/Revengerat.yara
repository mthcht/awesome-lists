rule Trojan_MSIL_Revengerat_SK_2147948719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Revengerat.SK!MTB"
        threat_id = "2147948719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revengerat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 7e 0b 00 00 04 06 07 91 6f 2d 00 00 0a 00 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

