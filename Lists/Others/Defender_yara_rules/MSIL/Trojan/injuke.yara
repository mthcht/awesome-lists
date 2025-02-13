rule Trojan_MSIL_injuke_NEAA_2147836324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/injuke.NEAA!MTB"
        threat_id = "2147836324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 17 00 00 06 20 e4 1d 29 81 20 47 c7 f9 e2 61 7e be 00 00 04 7b 34 01 00 04 61 28 48 00 00 06 6f 26 00 00 0a 13 09 20 00 00 00 00 7e 75 00 00 04 7b 11 00 00 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

