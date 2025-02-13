rule TrojanSpy_MSIL_Dedoal_A_2147695690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dedoal.A"
        threat_id = "2147695690"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dedoal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MonitoreWEB" ascii //weight: 1
        $x_1_2 = "SmartIrc4netWEB" ascii //weight: 1
        $x_1_3 = "DownAll" ascii //weight: 1
        $x_1_4 = "RestartaForUAC" ascii //weight: 1
        $x_1_5 = "DetectAV" ascii //weight: 1
        $x_1_6 = "GBExists" ascii //weight: 1
        $x_1_7 = "DetectAndClean" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

