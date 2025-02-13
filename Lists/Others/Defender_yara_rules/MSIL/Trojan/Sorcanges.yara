rule Trojan_MSIL_Sorcanges_A_2147728351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sorcanges.A"
        threat_id = "2147728351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sorcanges"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "orange.exe" ascii //weight: 10
        $x_10_2 = "orangeteghal" wide //weight: 10
        $x_10_3 = "Mive Narengi" wide //weight: 10
        $x_10_4 = "MPRESS" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

