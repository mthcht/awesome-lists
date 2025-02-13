rule PWS_MSIL_HtmStealer_A_2147764876_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/HtmStealer.A!MTB"
        threat_id = "2147764876"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HtmStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Token-Browser-Password-Stealer-Creator" ascii //weight: 1
        $x_1_2 = "/C choice /C Y /N /D Y /T 3 & Del \"" ascii //weight: 1
        $x_1_3 = "sendhookfile.exe" ascii //weight: 1
        $x_1_4 = "C:/temp/WebBrowserPassView.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

