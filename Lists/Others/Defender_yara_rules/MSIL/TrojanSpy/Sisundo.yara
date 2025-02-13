rule TrojanSpy_MSIL_Sisundo_A_2147706576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Sisundo.A"
        threat_id = "2147706576"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sisundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&param_sklog=" wide //weight: 1
        $x_1_2 = "UPLOAD_AND_RUN" wide //weight: 1
        $x_1_3 = "SAMP_INSTALL_STEALER" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

