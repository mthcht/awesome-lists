rule TrojanSpy_MSIL_Logadat_A_2147706581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Logadat.A"
        threat_id = "2147706581"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Logadat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OemPeriod" wide //weight: 1
        $x_1_2 = "Chrome\\User Data" wide //weight: 1
        $x_1_3 = "@gmail.com" wide //weight: 1
        $x_1_4 = "\\Start Menu\\Programs\\Startup\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

