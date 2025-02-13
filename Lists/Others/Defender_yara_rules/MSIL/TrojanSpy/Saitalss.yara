rule TrojanSpy_MSIL_Saitalss_A_2147688502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Saitalss.A"
        threat_id = "2147688502"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Saitalss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "log2@turkceventrilo.com" wide //weight: 1
        $x_1_2 = "log2klg@gmail.com" wide //weight: 1
        $x_1_3 = "E-Posta Konusu" wide //weight: 1
        $x_1_4 = "/printscreen.jpg" wide //weight: 1
        $x_1_5 = "Microsoft Application Readers" wide //weight: 1
        $x_1_6 = "MakeProcessUnkillable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

