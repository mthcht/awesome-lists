rule Trojan_MSIL_Gorgon_GJY_2147849275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gorgon.GJY!MTB"
        threat_id = "2147849275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gorgon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C thanh to" ascii //weight: 1
        $x_1_2 = "MyoZp3gZ6dBplJ4v36x" ascii //weight: 1
        $x_1_3 = "fQQBGCWA12yLKddaXFu" ascii //weight: 1
        $x_1_4 = "bfh9p8dTSL" ascii //weight: 1
        $x_1_5 = "FQheAR7BL4RrbNecEES" ascii //weight: 1
        $x_1_6 = "MU02p2LbSCFu0iqt50E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

