rule Trojan_MSIL_Suzqu_A_2147730530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Suzqu.A"
        threat_id = "2147730530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Suzqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 16 0b 2b 0e 06 07 06 07 91 1f 1a 61 d2 9c 07 17 58 0b}  //weight: 10, accuracy: High
        $x_20_2 = "Microsoft Defander Lab" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

