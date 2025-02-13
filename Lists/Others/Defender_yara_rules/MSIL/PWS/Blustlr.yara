rule PWS_MSIL_Blustlr_GA_2147795259_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Blustlr.GA!MTB"
        threat_id = "2147795259"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blustlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Microsoft.NET\\Framework\\v2.0.50727\\InstallUtil.exe" ascii //weight: 10
        $x_1_2 = "CryptoFileGrabber" ascii //weight: 1
        $x_1_3 = "\\Ethereum\\keystore" ascii //weight: 1
        $x_1_4 = "Subject" ascii //weight: 1
        $x_1_5 = "Attach" ascii //weight: 1
        $x_1_6 = "@TITLE Removing" ascii //weight: 1
        $x_1_7 = "\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" ascii //weight: 1
        $x_1_8 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_9 = "\\Stub\\Project1.vbp" ascii //weight: 1
        $x_1_10 = "GetKeyboardData" ascii //weight: 1
        $x_1_11 = "ScreenCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

