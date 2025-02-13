rule Trojan_MSIL_Reccoon_MBCV_2147844228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reccoon.MBCV!MTB"
        threat_id = "2147844228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 02 26 16 2b 02 26 16 00 00 00 00 00 20 10 22 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

