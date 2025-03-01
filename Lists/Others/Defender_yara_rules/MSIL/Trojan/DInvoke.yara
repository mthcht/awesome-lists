rule Trojan_MSIL_Dinvoke_GPA_2147902300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dinvoke.GPA!MTB"
        threat_id = "2147902300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dinvoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 00 71 00 51 00 c7 05 44 00 4d 00 41 00 c7 05 44 00 41 00 45 00 c7 05 44 00 41 00 41 00}  //weight: 5, accuracy: High
        $x_5_2 = {e2 05 52 00 34 00 67 00 e7 05 52 00 34 00 67 00 d4 05 40 00 39 00 54 00 cf 05 42 00 31 00 76}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

