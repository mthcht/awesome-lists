rule TrojanSpy_MSIL_Labapost_B_2147679813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Labapost.B"
        threat_id = "2147679813"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Labapost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CopyVideo_RunWorkerCompleted" ascii //weight: 3
        $x_3_2 = "set_ProcessusUndetected" ascii //weight: 3
        $x_4_3 = "ATS Labanquepostale Starter.exe" ascii //weight: 4
        $x_4_4 = "set_RARStatut" ascii //weight: 4
        $x_5_5 = "ATS_Labanquepostale_Starter.Resources.resources" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

