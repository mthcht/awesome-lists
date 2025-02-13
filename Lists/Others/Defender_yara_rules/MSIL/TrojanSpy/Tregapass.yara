rule TrojanSpy_MSIL_Tregapass_A_2147685536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Tregapass.A"
        threat_id = "2147685536"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tregapass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "henrique.wheels@yahoo.com" ascii //weight: 1
        $x_1_2 = "loginpassword" ascii //weight: 1
        $x_1_3 = "Phlm2010" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

