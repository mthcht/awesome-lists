rule PWS_MSIL_Vidar_B_2147959614_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Vidar.B!AMTB"
        threat_id = "2147959614"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://pgmaeavc.beget.tech" ascii //weight: 2
        $x_2_2 = "Add-MpPreference -ExclusionPath" ascii //weight: 2
        $x_1_3 = "WebClient" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

