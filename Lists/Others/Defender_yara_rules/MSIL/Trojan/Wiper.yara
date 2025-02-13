rule Trojan_MSIL_Wiper_E_2147731896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wiper.E"
        threat_id = "2147731896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Tests\\Console\\ProgectRevenge\\pure_goof\\" ascii //weight: 1
        $x_1_2 = "pure_goof.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

