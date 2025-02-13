rule Trojan_MSIL_Cretasker_A_2147740557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cretasker.A"
        threat_id = "2147740557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cretasker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rmxvd0xheW91dFBhbmVsMTY=" wide //weight: 1
        $x_1_2 = "ConfuserEx v1.0.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

