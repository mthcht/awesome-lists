rule Trojan_MSIL_HiddenTear_B_2147731307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/HiddenTear.B"
        threat_id = "2147731307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7ab0dd04-43e0-4d89-be59-60a30b766467" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

