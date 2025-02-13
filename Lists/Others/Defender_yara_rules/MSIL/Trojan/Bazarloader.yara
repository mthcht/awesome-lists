rule Trojan_MSIL_Bazarloader_MBEB_2147848735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bazarloader.MBEB!MTB"
        threat_id = "2147848735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bazarloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 0f 5d 13 16 11 07 11 0f 5b 13 17 11 0e 11 16 11 17 6f ?? 00 00 0a 13 34 11 11 11 10 12 34 28 ?? 00 00 0a 9c 11 10 17 58 13 10 11 07 17 58 13 07 11 07 11 0f 11 13 5a fe 04 13 18 11 18 2d be}  //weight: 1, accuracy: Low
        $x_1_2 = {13 12 20 01 e8 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

