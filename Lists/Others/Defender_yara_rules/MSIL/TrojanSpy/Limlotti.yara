rule TrojanSpy_MSIL_Limlotti_A_2147684525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Limlotti.A"
        threat_id = "2147684525"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Limlotti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--::]" wide //weight: 1
        $x_1_2 = "SetEPASSWORD" wide //weight: 1
        $x_1_3 = "FTPUpload" wide //weight: 1
        $x_1_4 = "Limitless Logger : : Keyboard Records : :" wide //weight: 1
        $x_1_5 = "Bitcoin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

