rule Trojan_MSIL_Vbato_A_2147637848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vbato.A"
        threat_id = "2147637848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vbato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ERRORDIR/(DIR).*(DIR).." wide //weight: 1
        $x_1_2 = "/RUNEXEFL/" wide //weight: 1
        $x_1_3 = "HTTPMail User Name" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

