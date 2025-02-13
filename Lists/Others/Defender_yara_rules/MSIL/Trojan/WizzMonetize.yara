rule Trojan_MSIL_WizzMonetize_LML_2147748487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WizzMonetize.LML!MTB"
        threat_id = "2147748487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WizzMonetize"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 [0-2] 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 03 07 91 09 61 d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = "EntryPoint" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

